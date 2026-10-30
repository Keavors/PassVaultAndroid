package com.example.passvault

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/*
 * Ядро PassVault для Android. Ни одного обращения к android.* — благодаря
 * этому весь файл проверяется обычными JVM-тестами (app/src/test), а не только
 * на устройстве.
 *
 * Формат файла vault.pmv — байт-в-байт тот же, что в ПК-версии:
 *
 *   PMVAULT2: magic(8) + id KDF(1) + time_cost(4) + память в КиБ(4) +
 *             parallelism(1) + соль(16) + nonce(12) + шифртекст
 *             ← ЕДИНСТВЕННЫЙ формат записи
 *
 *   PMVAULT1: magic(8) + итерации PBKDF2(4, BE) + соль(16) + nonce(12) + шифртекст
 *             ← только ЧТЕНИЕ, для файлов версий 1.x и 2.x
 *
 * Почему выброшен PBKDF2. Он считается процессором и почти не требует памяти,
 * поэтому видеокарта перебирает его тысячами попыток параллельно. Argon2id
 * требует 256 МиБ на КАЖДУЮ попытку, и преимущество видеокарты исчезает.
 * Держать рядом заведомо более слабый вариант незачем.
 *
 * Почему чтение PMVAULT1 остаётся навсегда: формат записан в первых восьми
 * байтах файла, и без разбора PMVAULT1 каждое существующее хранилище, каждый
 * .prev и каждый снимок в архиве стали бы нечитаемыми. Старый файл при первом
 * открытии сам переезжает на Argon2id (VaultRepo.open), сняв перед этим копию
 * в архив в ПРЕЖНЕМ формате.
 *
 * Argon2id считается чистой Java (BouncyCastle), нативная библиотека не нужна.
 */

// ---------------------------------------------------------------- криптография
object Crypto {
    val MAGIC: ByteArray = "PMVAULT1".toByteArray(Charsets.US_ASCII)
    val MAGIC_V2: ByteArray = "PMVAULT2".toByteArray(Charsets.US_ASCII)

    const val KDF_PBKDF2 = 1
    const val KDF_ARGON2ID = 2

    const val KDF_ITERATIONS = 600_000
    const val SALT_LEN = 16
    const val NONCE_LEN = 12
    private const val TAG_LEN = 16

    const val ARGON2_TIME_COST = 3
    const val ARGON2_MEMORY_KIB = 256 * 1024
    const val ARGON2_PARALLELISM = 4

    // Границы для значений, прочитанных ИЗ ФАЙЛА. Без проверки чужой или
    // повреждённый файл с максимальным uint32 вешает приложение на много минут
    // без возможности отмены.
    const val MIN_ITERATIONS = 10_000
    const val MAX_ITERATIONS = 20_000_000
    const val MAX_ARGON2_TIME_COST = 64
    const val MIN_ARGON2_MEMORY_KIB = 8
    const val MAX_ARGON2_MEMORY_KIB = 2 * 1024 * 1024
    const val MAX_ARGON2_PARALLELISM = 64

    class WrongPassword(msg: String) : Exception(msg)
    class BadFormat(msg: String) : Exception(msg)

    /** Описание того, как из мастер-пароля получается ключ. Как на ПК. */
    class KdfParams(
        val kdfId: Int,
        val salt: ByteArray,
        val iterations: Int = KDF_ITERATIONS,
        val timeCost: Int = ARGON2_TIME_COST,
        val memoryKib: Int = ARGON2_MEMORY_KIB,
        val parallelism: Int = ARGON2_PARALLELISM,
    ) {
        /** PMVAULT1 — старый формат, который только читается. */
        val isLegacy: Boolean get() = kdfId == KDF_PBKDF2

        /** Файл записан устаревшим KDF и подлежит переводу на Argon2id. */
        val needsUpgrade: Boolean get() = isLegacy

        fun withNewSalt() = KdfParams(kdfId, randomBytes(SALT_LEN), iterations,
            timeCost, memoryKib, parallelism)

        fun header(): ByteArray =
            if (isLegacy) MAGIC + intBE(iterations) + salt
            else MAGIC_V2 + byteArrayOf(KDF_ARGON2ID.toByte()) + intBE(timeCost) +
                    intBE(memoryKib) + byteArrayOf(parallelism.toByte()) + salt

        fun describe(): String =
            if (isLegacy) "PMVAULT1 · PBKDF2, $iterations итераций (старый формат)"
            else "PMVAULT2 · Argon2id, $timeCost прохода, ${memoryKib / 1024} МиБ, " +
                    "$parallelism потока"

        companion object {
            /** Параметры для ЛЮБОЙ новой записи. Единственный формат приложения. */
            fun default() = argon2id()

            fun argon2id(
                timeCost: Int = ARGON2_TIME_COST,
                memoryKib: Int = ARGON2_MEMORY_KIB,
                parallelism: Int = ARGON2_PARALLELISM,
            ) = KdfParams(KDF_ARGON2ID, randomBytes(SALT_LEN), timeCost = timeCost,
                memoryKib = memoryKib, parallelism = parallelism)

            /**
             * Устаревшие параметры PMVAULT1. Приложение таких файлов НЕ СОЗДАЁТ;
             * метод нужен, чтобы собрать параметры для чтения старого файла и
             * чтобы тесты могли такой файл изготовить.
             */
            fun pbkdf2(iterations: Int = KDF_ITERATIONS) =
                KdfParams(KDF_PBKDF2, randomBytes(SALT_LEN), iterations = iterations)
        }
    }

    /**
     * Argon2id — чистой Java (BouncyCastle), без нативных библиотек.
     *
     * Память берётся настоящая: 256 МиБ на телефоне это много, и на слабом
     * устройстве возможна нехватка памяти. Ловим её отдельно и говорим прямо,
     * а не выдаём «неверный пароль».
     */
    private fun argon2(password: CharArray, p: KdfParams): ByteArray {
        val params = org.bouncycastle.crypto.params.Argon2Parameters
            .Builder(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id)
            .withVersion(org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(p.timeCost)
            .withMemoryAsKB(p.memoryKib)
            .withParallelism(p.parallelism)
            .withSalt(p.salt)
            .build()
        val gen = org.bouncycastle.crypto.generators.Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(32)
        try {
            gen.generateBytes(password, out)
        } catch (e: OutOfMemoryError) {
            // Ссылаться тут на «Инструменты → Формат шифрования» больше нельзя:
            // такой кнопки нет ни на ПК, ни здесь, слабый формат убран.
            throw BadFormat(
                "Файлу нужно ${p.memoryKib / 1024} МиБ памяти для Argon2id, " +
                        "а телефону столько не выделить. Закрой другие приложения " +
                        "и попробуй снова."
            )
        }
        return out
    }

    fun deriveKey(password: CharArray, p: KdfParams): ByteArray = when (p.kdfId) {
        KDF_PBKDF2 -> {
            val spec = PBEKeySpec(password, p.salt, p.iterations, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val key = factory.generateSecret(spec).encoded
            spec.clearPassword()
            key
        }
        KDF_ARGON2ID -> argon2(password, p)
        else -> throw BadFormat("Неизвестный алгоритм получения ключа (id=${p.kdfId})")
    }

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }

    private fun intBE(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun beInt(b: ByteArray, off: Int) =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
                ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    fun encrypt(json: String, key: ByteArray, p: KdfParams): ByteArray {
        val nonce = randomBytes(NONCE_LEN)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val ct = c.doFinal(json.toByteArray(Charsets.UTF_8))
        return p.header() + nonce + ct
    }

    class Header(val params: KdfParams, val nonce: ByteArray, val ciphertext: ByteArray)

    /** Разбирает заголовок и проверяет его на разумность. */
    fun parse(blob: ByteArray): Header {
        if (blob.size >= MAGIC_V2.size &&
            blob.copyOfRange(0, MAGIC_V2.size).contentEquals(MAGIC_V2)
        ) {
            val minLen = MAGIC_V2.size + 1 + 4 + 4 + 1 + SALT_LEN + NONCE_LEN + TAG_LEN
            if (blob.size < minLen) throw BadFormat("Файл хранилища обрезан или повреждён")

            var off = MAGIC_V2.size
            val kdfId = blob[off].toInt() and 0xFF; off += 1
            if (kdfId != KDF_ARGON2ID)
                throw BadFormat("Неизвестный алгоритм получения ключа (id=$kdfId)")
            val timeCost = beInt(blob, off); off += 4
            val memoryKib = beInt(blob, off); off += 4
            val parallelism = blob[off].toInt() and 0xFF; off += 1

            if (timeCost < 1 || timeCost > MAX_ARGON2_TIME_COST)
                throw BadFormat("Недопустимый параметр time_cost в заголовке ($timeCost)")
            if (memoryKib < MIN_ARGON2_MEMORY_KIB || memoryKib > MAX_ARGON2_MEMORY_KIB)
                throw BadFormat("Недопустимый объём памяти в заголовке ($memoryKib КиБ)")
            if (parallelism < 1 || parallelism > MAX_ARGON2_PARALLELISM)
                throw BadFormat("Недопустимый параметр parallelism в заголовке ($parallelism)")

            val salt = blob.copyOfRange(off, off + SALT_LEN); off += SALT_LEN
            val nonce = blob.copyOfRange(off, off + NONCE_LEN); off += NONCE_LEN
            return Header(
                KdfParams(KDF_ARGON2ID, salt, timeCost = timeCost,
                    memoryKib = memoryKib, parallelism = parallelism),
                nonce, blob.copyOfRange(off, blob.size)
            )
        }

        val minLen = MAGIC.size + 4 + SALT_LEN + NONCE_LEN + TAG_LEN
        if (blob.size < minLen || !blob.copyOfRange(0, MAGIC.size).contentEquals(MAGIC))
            throw BadFormat("Это не файл хранилища PassVault (или он повреждён)")

        var off = MAGIC.size
        val iterations = beInt(blob, off); off += 4
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)
            throw BadFormat(
                "Недопустимое число итераций в заголовке ($iterations). " +
                        "Файл повреждён или подделан."
            )
        val salt = blob.copyOfRange(off, off + SALT_LEN); off += SALT_LEN
        val nonce = blob.copyOfRange(off, off + NONCE_LEN); off += NONCE_LEN
        return Header(KdfParams(KDF_PBKDF2, salt, iterations = iterations),
            nonce, blob.copyOfRange(off, blob.size))
    }

    private fun open(h: Header, key: ByteArray, wrongMsg: String): String {
        val plain = try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, h.nonce))
            c.doFinal(h.ciphertext)
        } catch (e: Exception) {
            throw WrongPassword(wrongMsg)
        }
        return String(plain, Charsets.UTF_8)
    }

    class Opened(val json: String, val key: ByteArray, val params: KdfParams)

    fun decrypt(blob: ByteArray, password: CharArray): Opened {
        val h = parse(blob)
        val key = deriveKey(password, h.params)
        val json = open(h, key, "Неверный мастер-пароль (или файл повреждён/подменён)")
        return Opened(json, key, h.params)
    }

    /**
     * Расшифровка готовым ключом, без прогона KDF.
     * Стоит доли миллисекунды, поэтому применима для проверки только что
     * записанного файла при каждом сохранении.
     */
    fun decryptWithKey(blob: ByteArray, key: ByteArray): String =
        open(parse(blob), key, "Файл не расшифровывается этим ключом")
}

// ---------------------------------------------------------------- метки времени
/**
 * Прежние версии писали "2026-01-31 14:05" — местное время, без секунд и без
 * часового пояса. Из-за этого правки внутри одной минуты неразличимы, а при
 * синхронизации между устройствами в разных поясах пометка «новее» врала.
 *
 * Теперь пишется ISO-8601 в UTC с секундами. Старый формат по-прежнему
 * читается (как местное время), поэтому существующие хранилища открываются
 * без конвертации.
 */
object Ts {
    private val ISO_OUT: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

    private val LEGACY: DateTimeFormatter = DateTimeFormatterBuilder()
        .appendPattern("yyyy-MM-dd HH:mm")
        .parseDefaulting(ChronoField.SECOND_OF_MINUTE, 0)
        .toFormatter()

    fun now(): String = ISO_OUT.format(Instant.now())

    /** Момент времени в миллисекундах или null, если строку разобрать не вышло. */
    fun parse(value: String?): Long? {
        if (value.isNullOrBlank()) return null
        val s = value.trim()
        try {
            return OffsetDateTime.parse(s).toInstant().toEpochMilli()
        } catch (_: Exception) {
        }
        try {
            return LocalDateTime.parse(s, LEGACY).atZone(ZoneId.systemDefault())
                .toInstant().toEpochMilli()
        } catch (_: Exception) {
        }
        try {
            return LocalDateTime.parse(s).atZone(ZoneId.systemDefault())
                .toInstant().toEpochMilli()
        } catch (_: Exception) {
        }
        return null
    }

    fun sortKey(value: String?): Long = parse(value) ?: Long.MIN_VALUE

    fun isNewer(a: String?, b: String?): Boolean = sortKey(a) > sortKey(b)

    /** Для показа пользователю — всегда в местном времени. */
    fun display(value: String?): String {
        val ms = parse(value) ?: return value ?: "?"
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(ms))
    }
}

// ---------------------------------------------------------------- генератор
object Gen {
    const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    const val DIGITS = "0123456789"
    const val DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?"

    /** Тот же набор, что на ПК, — иначе «исключить похожие» работало бы по-разному. */
    const val AMBIGUOUS = "Il1O0o5S2Z8B|`'\"{}[]()<>"

    class BadOptions(msg: String) : Exception(msg)

    fun defaults(): JSONObject = JSONObject().apply {
        put("use_lower", true); put("use_upper", true)
        put("use_digits", true); put("use_symbols", true)
        put("symbols", DEFAULT_SYMBOLS)
        put("require_each", true)
        put("exact_mode", true); put("exact_len", 16)
        put("min_len", 12); put("max_len", 20)
        put("required_chars", ""); put("excluded_chars", "")
        put("no_ambiguous", false)
    }

    fun generate(o: JSONObject): Pair<String, Int> {
        val rng = SecureRandom()
        val excluded = HashSet<Char>()
        o.optString("excluded_chars").forEach { excluded.add(it) }
        if (o.optBoolean("no_ambiguous")) AMBIGUOUS.forEach { excluded.add(it) }

        val selected = ArrayList<Pair<String, String>>()
        if (o.optBoolean("use_lower", true)) selected.add("строчные латинские" to LOWER)
        if (o.optBoolean("use_upper", true)) selected.add("заглавные латинские" to UPPER)
        if (o.optBoolean("use_digits", true)) selected.add("цифры" to DIGITS)
        if (o.optBoolean("use_symbols", true)) {
            val symbols = o.optString("symbols", DEFAULT_SYMBOLS)
            // Раньше пустой набор молча игнорировался: галочка стоит,
            // спецсимволов нет, и «минимум по одному из группы» их не даёт.
            if (symbols.isEmpty())
                throw BadOptions("Включены спецсимволы, но их набор пуст — впиши символы или сними галочку")
            selected.add("спецсимволы" to symbols)
        }

        val pools = ArrayList<List<Char>>()
        for ((name, group) in selected) {
            val p = group.toCharArray().distinct().filter { it !in excluded }
            if (p.isEmpty())
                throw BadOptions(
                    "Группа «$name» целиком попала в исключения — убери исключения " +
                            "или сними галочку с этой группы"
                )
            pools.add(p)
        }

        val required = o.optString("required_chars").toCharArray()
            .distinct().filter { !it.isWhitespace() }
        val conflict = required.filter { it in excluded }
        if (conflict.isNotEmpty())
            throw BadOptions("Символы «${conflict.joinToString("")}» одновременно и обязательны, и исключены")

        val pool = (pools.flatten() + required).distinct().sorted()
        if (pool.isEmpty())
            throw BadOptions("Набор символов пуст: включи хотя бы одну группу или впиши обязательные символы")

        var length = if (o.optBoolean("exact_mode", true)) {
            o.optInt("exact_len", 16)
        } else {
            var lo = o.optInt("min_len", 12)
            var hi = o.optInt("max_len", 20)
            if (lo > hi) { val t = lo; lo = hi; hi = t }
            lo + rng.nextInt(hi - lo + 1)
        }
        length = length.coerceIn(1, 512)

        val guaranteed = ArrayList(required)
        if (o.optBoolean("require_each", true))
            for (p in pools) guaranteed.add(p[rng.nextInt(p.size)])
        if (guaranteed.size > length)
            throw BadOptions(
                "Обязательных символов (${guaranteed.size}) больше, чем длина пароля ($length) — увеличь длину"
            )

        val chars = ArrayList(guaranteed)
        repeat(length - guaranteed.size) { chars.add(pool[rng.nextInt(pool.size)]) }
        for (i in chars.indices.reversed()) {          // тасование Фишера–Йетса
            if (i == 0) break
            val j = rng.nextInt(i + 1)
            val t = chars[i]; chars[i] = chars[j]; chars[j] = t
        }
        return Pair(chars.joinToString(""), pool.size)
    }

    /**
     * Осторожная нижняя оценка стойкости. Символы из «обязательно включить»
     * предсказуемы, поэтому в зачёт не идут: для менеджера паролей завышать
     * эту цифру — худшее из зол.
     */
    fun estimateBits(o: JSONObject, length: Int, poolSize: Int): Double {
        if (poolSize <= 1 || length <= 0) return 0.0
        val forced = o.optString("required_chars").toCharArray()
            .distinct().count { !it.isWhitespace() }
        val free = (length - forced).coerceAtLeast(0)
        return free * (Math.log(poolSize.toDouble()) / Math.log(2.0))
    }

    fun rate(bits: Double): String = when {
        bits < 45 -> "слабый"
        bits < 64 -> "средний"
        bits < 80 -> "хороший"
        else -> "отличный"
    }
}

// ---------------------------------------------------------------- модель данных
class PastPassword(val password: String, val changed: String) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("password", password); put("changed", changed)
    }
}

class Entry(
    var id: String,
    var title: String = "",
    var login: String = "",
    var password: String = "",
    var url: String = "",
    var notes: String = "",
    var created: String = "",
    var modified: String = "",
    var deleted: Boolean = false,
    var history: MutableList<PastPassword> = mutableListOf(),
) {
    /**
     * Поля, которых эта версия приложения не знает.
     *
     * Хранить их обязательно: без этого телефон при первом же сохранении
     * молча выбрасывал бы всё, что добавила более новая версия на ПК, и
     * данные пропадали бы при каждой синхронизации.
     */
    private var extras: JSONObject = JSONObject()

    fun toJson(): JSONObject {
        val j = JSONObject()
        extras.keys().forEach { k -> j.put(k, extras.get(k)) }
        j.put("id", id); j.put("title", title); j.put("login", login)
        j.put("password", password); j.put("url", url); j.put("notes", notes)
        j.put("created", created); j.put("modified", modified)
        if (deleted) j.put("deleted", true) else j.remove("deleted")
        if (history.isEmpty()) j.remove("history")
        else j.put("history", JSONArray().also { arr -> history.forEach { arr.put(it.toJson()) } })
        return j
    }

    fun contentEquals(o: Entry): Boolean =
        title == o.title && login == o.login && password == o.password &&
                url == o.url && notes == o.notes && deleted == o.deleted

    fun copyContentFrom(o: Entry) {
        title = o.title; login = o.login; password = o.password
        url = o.url; notes = o.notes; created = o.created
        modified = o.modified; deleted = o.deleted
        history = ArrayList(o.history)
        // Копия, а не ссылка: иначе две записи начинают делить один объект, и
        // правка незнакомых полей в одной молча меняет другую.
        extras = JSONObject(o.extras.toString())
    }

    /** Кладёт прежний пароль в историю. Закрывает «перезаписал и потерял старый». */
    fun pushHistory(old: String) {
        if (old.isEmpty()) return
        if (history.isNotEmpty() && history[0].password == old) return
        history.add(0, PastPassword(old, Ts.now()))
        while (history.size > MAX_HISTORY) history.removeAt(history.size - 1)
    }

    val displayTitle: String get() = title.ifBlank { "(без названия)" }

    companion object {
        const val MAX_HISTORY = 10
        private val KNOWN = setOf(
            "id", "title", "login", "password", "url", "notes",
            "created", "modified", "deleted", "history"
        )

        fun fromJson(j: JSONObject): Entry {
            val hist = mutableListOf<PastPassword>()
            j.optJSONArray("history")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val h = arr.optJSONObject(i) ?: continue
                    val p = h.optString("password", "")
                    if (p.isNotEmpty()) hist.add(PastPassword(p, h.optString("changed", "")))
                }
            }
            val e = Entry(
                id = j.optString("id"),
                title = j.optString("title"),
                login = j.optString("login"),
                password = j.optString("password"),
                url = j.optString("url"),
                notes = j.optString("notes"),
                created = j.optString("created"),
                modified = j.optString("modified"),
                deleted = j.optBoolean("deleted", false),
                history = hist,
            )
            val rest = JSONObject()
            j.keys().forEach { k -> if (k !in KNOWN) rest.put(k, j.get(k)) }
            e.extras = rest
            if (e.id.isBlank()) e.id = newId()
            if (e.created.isBlank()) e.created = Ts.now()
            if (e.modified.isBlank()) e.modified = Ts.now()
            return e
        }

        fun newId(): String =
            Crypto.randomBytes(8).joinToString("") { "%02x".format(it) }

        fun fresh(): Entry {
            val t = Ts.now()
            return Entry(id = newId(), title = "Новая запись", created = t, modified = t)
        }
    }
}

// ---------------------------------------------------------------- запись на диск
/**
 * Прежняя реализация записи копировала предыдущую версию в .bak при каждом
 * сохранении, а сохранение идёт при каждом уходе с экрана. Такой .bak — не
 * резервная копия, а «шаг назад», причём ненадёжный.
 *
 * Здесь: файл сначала пишется во временный, проверяется расшифровкой (ключ уже
 * в памяти), затем прежняя версия КОПИРУЕТСЯ в .prev, и только потом временный
 * файл занимает место основного. Хранилище не исчезает с диска ни на миг.
 */
object VaultIO {
    const val FILE_NAME = "vault.pmv"
    const val PREV_SUFFIX = ".prev"
    const val TMP_SUFFIX = ".tmp"
    const val LEGACY_BAK_SUFFIX = ".bak"

    class WriteFailed(msg: String) : Exception(msg)

    fun vaultFile(dir: File) = File(dir, FILE_NAME)

    fun writeAtomic(target: File, blob: ByteArray, verifyKey: ByteArray?) {
        val tmp = File(target.parentFile, target.name + TMP_SUFFIX)
        try {
            // fsync обязателен: без него файл считается записанным, а на диск
            // ещё ничего не легло, и внезапное выключение телефона оставляет
            // пустой или обрезанный vault.pmv.
            java.io.FileOutputStream(tmp).use { out ->
                out.write(blob)
                out.flush()
                out.fd.sync()
            }
        } catch (e: Exception) {
            tmp.delete()
            throw WriteFailed("Не удалось записать файл: ${e.message}")
        }

        if (verifyKey != null) {
            try {
                Crypto.decryptWithKey(tmp.readBytes(), verifyKey)
            } catch (e: Exception) {
                tmp.delete()
                throw WriteFailed(
                    "Записанный файл не проходит проверку целостности, сохранение " +
                            "отменено (прежняя версия цела): ${e.message}"
                )
            }
        }

        if (target.exists()) {
            try {
                target.copyTo(File(target.parentFile, target.name + PREV_SUFFIX), overwrite = true)
            } catch (_: Exception) {
                // Не смогли обновить .prev — актуальные данные важнее предыдущей версии.
            }
        }

        if (!tmp.renameTo(target)) {
            try {
                target.writeBytes(blob)
                tmp.delete()
            } catch (e: Exception) {
                throw WriteFailed("Не удалось заменить файл хранилища: ${e.message}")
            }
        }
    }

    class Candidate(val file: File, val note: String) {
        val modified: Long get() = file.lastModified()
    }

    /** Файлы, из которых можно восстановиться, если vault.pmv пропал. */
    fun recoveryCandidates(dir: File): List<Candidate> {
        val out = ArrayList<Candidate>()
        val named = listOf(
            File(dir, FILE_NAME + PREV_SUFFIX) to "предыдущая версия",
            File(dir, FILE_NAME + TMP_SUFFIX) to "недописанный файл последнего сохранения",
            File(dir, FILE_NAME + LEGACY_BAK_SUFFIX) to "копия от прежней версии приложения",
        )
        for ((f, note) in named) if (f.isFile) out.add(Candidate(f, note))
        for (s in Backups.list(dir)) out.add(Candidate(s.file, "снимок из архива"))

        return out.filter { looksLikeVault(it.file) }.sortedByDescending { it.modified }
    }

    private fun looksLikeVault(f: File): Boolean = try {
        val head = ByteArray(8)
        f.inputStream().use { it.read(head) }
        head.contentEquals(Crypto.MAGIC) || head.contentEquals(Crypto.MAGIC_V2)
    } catch (_: Exception) {
        false
    }
}

// ---------------------------------------------------------------- архив снимков
/**
 * Снимки в том же зашифрованном формате и с теми же именами, что на ПК, —
 * файлы взаимозаменяемы между устройствами.
 *
 * Ротация «дед-отец-сын»: последние 12, почасовые за сутки, дневные за месяц,
 * месячные за год, плюс событийные (перед слиянием и сменой пароля).
 */
object Backups {
    const val DIR_NAME = "vault_backups"
    const val KEEP_RECENT = 12
    const val KEEP_HOURLY = 24
    const val KEEP_DAILY = 30
    const val KEEP_MONTHLY = 12
    const val KEEP_EVENT = 10
    const val MIN_INTERVAL_MS = 5 * 60 * 1000L

    private val NAME_RE = Regex("^snap-(\\d{8})-(\\d{6})(?:-([a-z0-9]+))?\\.pmv$")
    private val STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")

    /** Метки событий совпадают с ПК-версией: снимки взаимозаменяемы. */
    val EVENT_LABELS = mapOf(
        "premerge" to "перед слиянием",
        "prepassword" to "перед сменой пароля",
        "preformat" to "перед сменой формата",
        "prerestore" to "перед восстановлением",
        "prepurge" to "перед чисткой",
        "preimport" to "перед импортом",
        "legacybak" to "копия от версии 1.x",
        "legacyprev" to "откат от прежней версии",
        "legacytmp" to "недописанный файл прежней версии"
    )

    class Snapshot(val file: File, val at: LocalDateTime, val tag: String?) {
        val isEvent: Boolean get() = tag != null
        val size: Long get() = file.length()

        fun label(): String {
            val base = at.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
            return if (tag == null) base else "$base  ·  ${EVENT_LABELS[tag] ?: tag}"
        }
    }

    fun dir(filesDir: File) = File(filesDir, DIR_NAME)

    fun list(filesDir: File): List<Snapshot> {
        val d = dir(filesDir)
        val files = d.listFiles() ?: return emptyList()
        val out = ArrayList<Snapshot>()
        for (f in files) {
            val m = NAME_RE.find(f.name) ?: continue
            val at = try {
                LocalDateTime.parse(m.groupValues[1] + "-" + m.groupValues[2], STAMP)
            } catch (_: Exception) {
                continue
            }
            out.add(Snapshot(f, at, m.groupValues[3].ifBlank { null }))
        }
        return out.sortedByDescending { it.at }
    }

    fun totalSize(filesDir: File): Long = list(filesDir).sumOf { it.size }

    /**
     * Отпечаток содержимого, а не шифртекста: шифртекст меняется при каждом
     * сохранении из-за нового nonce, и по нему архив забился бы копиями.
     */
    fun digest(json: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(json.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    /**
     * Пишет снимок ИЗ ТЕХ ЖЕ БАЙТОВ, что только что легли в vault.pmv.
     *
     * Прежняя версия копировала файл с диска, а отпечаток считала по данным в
     * памяти, и эти двое расходились: после событийного снимка ближайшее
     * сохранение решало, что менять нечего, и штатный снимок пропускало.
     * Байты и отпечаток теперь приходят одной парой и разойтись не могут.
     */
    fun write(filesDir: File, blob: ByteArray, tag: String? = null,
              now: LocalDateTime = LocalDateTime.now()): Snapshot? {
        val d = dir(filesDir)
        if (!d.exists() && !d.mkdirs()) return null

        // Два события в одну секунду сдвигаются, а не затирают друг друга.
        var dest: File? = null
        var at = now
        for (shift in 0 until 60) {
            val t = now.plusSeconds(shift.toLong())
            val name = "snap-" + t.format(STAMP) + (if (tag != null) "-$tag" else "") + ".pmv"
            val candidate = File(d, name)
            if (!candidate.exists()) { dest = candidate; at = t; break }
        }
        val target = dest ?: return null

        val tmp = File(d, target.name + ".tmp")
        try {
            // fsync, как и для самого хранилища. Без него файл считается
            // записанным, а на диск ещё ничего не легло: внезапное выключение
            // телефона оставляет пустой или обрезанный снимок — то есть
            // резервную копию, которой нельзя воспользоваться.
            java.io.FileOutputStream(tmp).use { out ->
                out.write(blob)
                out.flush()
                out.fd.sync()
            }
            if (!tmp.renameTo(target)) { target.writeBytes(blob); tmp.delete() }
        } catch (_: Exception) {
            tmp.delete()
            return null
        }
        prune(filesDir)
        return Snapshot(target, at, tag)
    }

    fun prune(filesDir: File): Int {
        val snaps = list(filesDir)
        val keep = HashSet<String>()

        snaps.filter { it.isEvent }.take(KEEP_EVENT).forEach { keep.add(it.file.path) }
        val auto = snaps.filter { !it.isEvent }
        auto.take(KEEP_RECENT).forEach { keep.add(it.file.path) }

        fun buckets(pattern: String, limit: Int) {
            val fmt = DateTimeFormatter.ofPattern(pattern)
            val seen = HashSet<String>()
            for (s in auto) {
                val b = s.at.format(fmt)
                if (!seen.add(b)) continue
                keep.add(s.file.path)
                if (seen.size >= limit) break
            }
        }
        buckets("yyyyMMddHH", KEEP_HOURLY)
        buckets("yyyyMMdd", KEEP_DAILY)
        buckets("yyyyMM", KEEP_MONTHLY)

        var removed = 0
        for (s in snaps) if (s.file.path !in keep && s.file.delete()) removed++
        return removed
    }
}

// ---------------------------------------------------------------- хранилище
object VaultRepo {
    const val FILE_NAME = VaultIO.FILE_NAME
    const val TOMBSTONE_TTL_DAYS = 180L

    var entries: MutableList<Entry> = mutableListOf()
    var settings: JSONObject = JSONObject()

    /**
     * Ключи КОРНЯ JSON, о которых это приложение не знает.
     *
     * Хранить их обязательно ровно по той же причине, что и незнакомые поля
     * записи: иначе телефон при первом же сохранении молча выбрасывал бы всё,
     * что положила в корень файла более новая версия на ПК. У записей это было
     * сделано, у корня — нет: toJsonString() писал ровно version/entries/
     * settings, и остальное исчезало.
     */
    private var rootExtras: JSONObject = JSONObject()

    private var key: ByteArray? = null
    private var params: Crypto.KdfParams? = null
    private var lastActive: Long = 0L
    private var lastDigest: String? = null
    private var lastSnapshotAt: Long = 0L

    val unlocked get() = key != null

    /** Описание текущего формата — для экрана «О программе». */
    fun formatDescription(): String = params?.describe() ?: "хранилище закрыто"

    fun file(filesDir: File): File = VaultIO.vaultFile(filesDir)

    fun now(): String = Ts.now()

    fun autoLockMs(): Long =
        (appSettings().optInt("autolock_minutes", 5).coerceIn(1, 180)) * 60_000L

    fun touch() { lastActive = System.currentTimeMillis() }
    fun expired() = unlocked && System.currentTimeMillis() - lastActive > autoLockMs()

    fun lock() {
        key = null; params = null
        entries = mutableListOf()
        settings = JSONObject()
        rootExtras = JSONObject()
        lastDigest = null
    }

    fun genSettings(): JSONObject {
        var g = settings.optJSONObject("generator")
        if (g == null) { g = Gen.defaults(); settings.put("generator", g) }
        val d = Gen.defaults()
        d.keys().forEach { k -> if (!g.has(k)) g.put(k, d.get(k)) }
        return g
    }

    fun appSettings(): JSONObject {
        var a = settings.optJSONObject("app")
        if (a == null) { a = JSONObject(); settings.put("app", a) }
        if (!a.has("autolock_minutes")) a.put("autolock_minutes", 5)
        if (!a.has("clipboard_seconds")) a.put("clipboard_seconds", 30)
        return a
    }

    fun toJsonString(): String {
        val root = JSONObject()
        // Сначала незнакомые ключи корня, потом свои — свои главнее.
        rootExtras.keys().forEach { k -> root.put(k, rootExtras.get(k)) }
        root.put("version", 1)
        val arr = JSONArray()
        entries.forEach { arr.put(it.toJson()) }
        root.put("entries", arr)
        genSettings(); appSettings()
        root.put("settings", settings)
        return root.toString()
    }

    private fun loadJson(json: String) {
        val root = JSONObject(json)
        val version = root.optInt("version", 1)
        if (version > 1)
            throw Crypto.BadFormat(
                "Файл создан более новой версией PassVault (версия данных $version). " +
                        "Обнови приложение, иначе данные можно потерять."
            )
        val arr = root.optJSONArray("entries") ?: JSONArray()
        val seen = HashSet<String>()
        val list = ArrayList<Entry>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val e = Entry.fromJson(obj)
            while (!seen.add(e.id)) e.id = Entry.newId()   // дубликаты id ломают слияние
            list.add(e)
        }
        entries = list
        settings = root.optJSONObject("settings") ?: JSONObject()
        genSettings(); appSettings()

        val rest = JSONObject()
        root.keys().forEach { k -> if (k !in KNOWN_ROOT_KEYS) rest.put(k, root.get(k)) }
        rootExtras = rest
    }

    private val KNOWN_ROOT_KEYS = setOf("version", "entries", "settings")

    /**
     * Открывает хранилище. Возвращает короткие сообщения для пользователя:
     * что обновилось, что не получилось.
     *
     * Считает KDF, то есть на Argon2id занимает секунды. Вызывать из фонового
     * потока — на главном это гарантированный ANR.
     */
    fun open(filesDir: File, password: CharArray): List<String> {
        val blob = file(filesDir).readBytes()
        val op = try {
            Crypto.decrypt(blob, password)
        } catch (e: Crypto.WrongPassword) {
            Throttle.recordFailure(filesDir)
            throw e
        }
        Throttle.recordSuccess(filesDir)
        key = op.key; params = op.params
        loadJson(op.json)
        // Содержимое только что прочитано с диска и ему же равно — снимать
        // копию того, что и так лежит нетронутым, незачем.
        lastDigest = Backups.digest(toJsonString())
        touch()

        val notes = ArrayList<String>()
        notes += upgradeKdfIfNeeded(filesDir, password)
        notes += firstSnapshotIfArchiveEmpty(filesDir)
        return notes
    }

    /**
     * Переводит хранилище со старого PBKDF2 на Argon2id. Один раз, само.
     *
     * Порядок важен. Снимок делается ДО смены ключа и ложится в архив
     * зашифрованным ПРЕЖНИМ способом: если перешифровка не доедет, у человека
     * останется читаемая копия. При любой ошибке записи ключ и параметры
     * откатываются, и работа продолжается на старом формате — потерять доступ
     * к уже открытому хранилищу из-за неудачного апгрейда недопустимо.
     */
    /** Параметры, на которые переводится старый файл. Подменяются в тестах. */
    var upgradeParams: () -> Crypto.KdfParams = { Crypto.KdfParams.default() }

    private fun upgradeKdfIfNeeded(filesDir: File, password: CharArray): List<String> {
        val p = params ?: return emptyList()
        if (!p.needsUpgrade) return emptyList()

        try {
            snapshot(filesDir, "preformat")
        } catch (e: Exception) {
            return listOf("Хранилище не переведено на Argon2id " +
                    "(не удалось сделать копию): ${e.message}")
        }

        val oldKey = key
        val oldParams = params
        return try {
            params = upgradeParams()
            key = Crypto.deriveKey(password, params!!)
            save(filesDir)
            listOf("Хранилище переведено на усиленное шифрование (Argon2id). " +
                    "Мастер-пароль прежний.")
        } catch (e: Exception) {
            key = oldKey; params = oldParams
            listOf("Хранилище НЕ переведено на Argon2id: ${e.message}")
        }
    }

    /**
     * Первый снимок, если архив пуст.
     *
     * Штатный снимок делается только при изменении содержимого, поэтому на
     * свежей установке архив оставался пустым до первой правки: из всех
     * резервных копий существовал только vault.pmv.prev.
     */
    private fun firstSnapshotIfArchiveEmpty(filesDir: File): List<String> {
        if (Backups.list(filesDir).isNotEmpty()) return emptyList()
        return try {
            if (snapshot(filesDir, null) != null)
                listOf("Создан первый снимок в архиве копий") else emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Создаёт пустое хранилище. Раньше здесь стоял pbkdf2(), и каждое новое
     * хранилище на телефоне получало слабейший из двух вариантов.
     *
     * kdf передаётся только тестами: настоящие 256 МиБ Argon2id в юнит-тестах
     * гонять незачем — проверяется логика вокруг формата, а не стойкость KDF.
     */
    fun create(filesDir: File, password: CharArray,
               kdf: Crypto.KdfParams = Crypto.KdfParams.default()) {
        entries = mutableListOf()
        settings = JSONObject()
        rootExtras = JSONObject()
        genSettings(); appSettings()
        params = kdf
        key = Crypto.deriveKey(password, kdf)
        save(filesDir)
        touch()
    }

    fun passwordMatches(password: CharArray): Boolean {
        val k = key ?: return false
        val p = params ?: return false
        return MessageDigest.isEqual(Crypto.deriveKey(password, p), k)
    }

    fun changePassword(filesDir: File, current: CharArray, newPass: CharArray): Boolean {
        if (!passwordMatches(current)) return false
        snapshot(filesDir, "prepassword")
        val oldKey = key; val oldParams = params
        params = params!!.withNewSalt()
        key = Crypto.deriveKey(newPass, params!!)
        try {
            save(filesDir)
        } catch (e: Exception) {
            // Откат: иначе ключ в памяти разъедется с ключом файла, и следующее
            // сохранение молча перешифрует хранилище новым паролем.
            key = oldKey; params = oldParams
            throw e
        }
        return true
    }

    /**
     * Записывает хранилище. Бросает VaultIO.WriteFailed при неудаче.
     *
     * nowMs передаётся только тестами: ротацию снимков иначе не проверить, не
     * заставляя тест ждать пять минут.
     */
    fun save(filesDir: File, nowMs: Long = System.currentTimeMillis()) {
        val k = key ?: return
        val json = toJsonString()
        val blob = Crypto.encrypt(json, k, params!!)
        VaultIO.writeAtomic(file(filesDir), blob, k)

        val d = Backups.digest(json)
        if (d == lastDigest) return
        if (lastSnapshotAt != 0L && nowMs - lastSnapshotAt < Backups.MIN_INTERVAL_MS) {
            lastDigest = d
            return
        }
        val at = java.time.Instant.ofEpochMilli(nowMs)
            .atZone(java.time.ZoneId.systemDefault()).toLocalDateTime()
        if (Backups.write(filesDir, blob, null, at) != null) {
            lastDigest = d
            lastSnapshotAt = nowMs
        }
    }

    /**
     * Снимок по событию — делается всегда, и сначала сохраняет несохранённое.
     *
     * Без сохранения «снимок перед слиянием» снял бы состояние файла на диске,
     * а не то, что пользователь видит на экране, и обещание «откатимся, если
     * что» оказалось бы враньём.
     */
    fun snapshot(filesDir: File, tag: String? = null,
                 nowMs: Long = System.currentTimeMillis()): Backups.Snapshot? {
        val k = key ?: return null
        val json = toJsonString()
        val blob = Crypto.encrypt(json, k, params!!)
        VaultIO.writeAtomic(file(filesDir), blob, k)

        val at = java.time.Instant.ofEpochMilli(nowMs)
            .atZone(java.time.ZoneId.systemDefault()).toLocalDateTime()
        val s = Backups.write(filesDir, blob, tag, at)
        if (s != null) {
            lastDigest = Backups.digest(json)
            lastSnapshotAt = nowMs
        }
        return s
    }

    fun exportBlob(): ByteArray = Crypto.encrypt(toJsonString(), key!!, params!!)

    /**
     * Пробует открыть чужой файл текущим ключом.
     * Чаще всего это свой же снимок или копия с ПК под тем же паролем —
     * тогда спрашивать пароль повторно незачем.
     */
    fun tryOpenWithCurrentKey(blob: ByteArray): String? {
        val k = key ?: return null
        return try {
            Crypto.decryptWithKey(blob, k)
        } catch (_: Exception) {
            null
        }
    }

    /** Записи из расшифрованного JSON чужого хранилища. */
    fun parseEntries(json: String): List<Entry> {
        val arr = JSONObject(json).optJSONArray("entries") ?: JSONArray()
        val out = ArrayList<Entry>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            out.add(Entry.fromJson(obj))
        }
        return out
    }

    /** Импорт: только добавляет, существующие записи не трогает. */
    fun addEntries(incoming: List<Entry>): Int {
        val ids = entries.mapTo(HashSet()) { it.id }
        var added = 0
        for (e in incoming) {
            while (!ids.add(e.id)) e.id = Entry.newId()
            entries.add(e)
            added++
        }
        return added
    }

    fun entryById(id: String) = entries.firstOrNull { it.id == id }

    fun live() = entries.filter { !it.deleted }
    fun trashed() = entries.filter { it.deleted }

    fun softDelete(e: Entry) { e.deleted = true; e.modified = Ts.now() }
    fun restore(e: Entry) { e.deleted = false; e.modified = Ts.now() }

    /**
     * Надгробия старше порога. Порог намеренно большой: удаление должно успеть
     * разойтись на все устройства, иначе ПК при слиянии вернёт запись обратно.
     */
    fun purgeableTombstones(nowMs: Long = System.currentTimeMillis()): List<Entry> {
        val cutoff = nowMs - TOMBSTONE_TTL_DAYS * 86_400_000L
        return entries.filter {
            val k = Ts.parse(it.modified)
            it.deleted && k != null && k < cutoff
        }
    }

    fun purgeTombstones(nowMs: Long = System.currentTimeMillis()): Int {
        val doomed = purgeableTombstones(nowMs).toHashSet()
        if (doomed.isEmpty()) return 0
        val before = entries.size
        entries = entries.filter { it !in doomed }.toMutableList()
        return before - entries.size
    }
}

// ---------------------------------------------------------------- задержка попыток
/**
 * Задержка после неверных мастер-паролей: три попытки — пауза, дальше пауза
 * растёт (5 с, 30 с, 2 мин, 10 мин, 30 мин).
 *
 * Честно о том, чего это НЕ даёт: файл хранилища всё равно можно перебирать
 * чем угодно, минуя приложение, — от этого защищает KDF, а не пауза. Здесь
 * закрывается другой случай: чужие руки на разблокированном телефоне.
 *
 * Состояние лежит на диске, поэтому перезапуск приложения паузу не снимает.
 * Учитывается и перевод часов назад: если «сейчас» раньше начала паузы, часы
 * двигали, и пауза отсчитывается заново.
 */
object Throttle {
    const val FILE_NAME = "attempts.json"
    const val ATTEMPTS_PER_STEP = 3
    val LADDER = intArrayOf(5, 30, 120, 600, 1800)

    private fun file(dir: File) = File(dir, FILE_NAME)

    private fun load(dir: File): JSONObject = try {
        JSONObject(file(dir).readText())
    } catch (_: Exception) {
        JSONObject()
    }

    private fun save(dir: File, o: JSONObject) {
        try {
            file(dir).writeText(o.toString())
        } catch (_: Exception) {
        }
    }

    fun failures(dir: File): Int = load(dir).optInt("failures", 0).coerceAtLeast(0)

    private fun delayFor(failures: Int): Int {
        val step = failures / ATTEMPTS_PER_STEP
        if (step <= 0) return 0
        return LADDER[minOf(step - 1, LADDER.size - 1)]
    }

    /** Сколько секунд осталось ждать. 0 — можно пробовать. */
    fun remaining(dir: File, nowMs: Long = System.currentTimeMillis()): Int {
        val data = load(dir)
        if (!data.has("locked_until")) return 0
        val until = data.optLong("locked_until", 0L)
        val started = data.optLong("locked_at", 0L)

        if (started > 0 && nowMs < started - 1000) {
            val delay = delayFor(failures(dir))
            save(dir, JSONObject().apply {
                put("failures", failures(dir))
                put("locked_at", nowMs)
                put("locked_until", nowMs + delay * 1000L)
            })
            return delay
        }
        val left = until - nowMs
        return if (left > 0) (left / 1000).toInt() + 1 else 0
    }

    fun isLocked(dir: File, nowMs: Long = System.currentTimeMillis()) = remaining(dir, nowMs) > 0

    fun attemptsLeft(dir: File): Int {
        if (isLocked(dir)) return 0
        return ATTEMPTS_PER_STEP - (failures(dir) % ATTEMPTS_PER_STEP)
    }

    /** Отмечает неверный пароль. Возвращает секунды паузы (0 — паузы нет). */
    fun recordFailure(dir: File, nowMs: Long = System.currentTimeMillis()): Int {
        val n = failures(dir) + 1
        val o = JSONObject().put("failures", n)
        if (n % ATTEMPTS_PER_STEP == 0) {
            val delay = delayFor(n)
            o.put("locked_at", nowMs)
            o.put("locked_until", nowMs + delay * 1000L)
            save(dir, o)
            return delay
        }
        save(dir, o)
        return 0
    }

    fun recordSuccess(dir: File) {
        if (!file(dir).delete()) save(dir, JSONObject().put("failures", 0))
    }

    fun humanDelay(seconds: Int): String = when {
        seconds < 60 -> "$seconds с"
        seconds < 3600 -> "${Math.round(seconds / 60.0)} мин"
        else -> "%.1f ч".format(seconds / 3600.0)
    }
}

// ---------------------------------------------------------------- CSV и JSON
/**
 * Экспорт и импорт в открытых форматах. Раньше этого на телефоне не было
 * вовсе: данные доставались только самим приложением и только в его формате,
 * то есть пользователь был к нему привязан. Для хранилища паролей такая
 * привязка недопустима.
 *
 * Правила разбора те же, что в ПК-версии (pvault/portable.py), включая
 * распознавание заголовков Bitwarden и KeePass, — файл, собранный на одном
 * устройстве, обязан читаться на другом.
 *
 * ФАЙЛЫ НЕ ЗАШИФРОВАНЫ. Интерфейс обязан предупреждать об этом до, а не после.
 */
object Portable {
    val COLUMNS = listOf("title", "login", "password", "url", "notes",
                         "created", "modified")

    class BadImport(msg: String) : Exception(msg)

    /** Заголовки чужих выгрузок -> наши поля. Список совпадает с ПК-версией. */
    private val ALIASES = mapOf(
        "title" to "title", "name" to "title", "account" to "title",
        "имя" to "title", "название" to "title", "заголовок" to "title",

        "login" to "login", "username" to "login", "user name" to "login",
        "login name" to "login", "login_username" to "login", "user" to "login",
        "email" to "login", "e-mail" to "login", "логин" to "login",

        "password" to "password", "login_password" to "password",
        "пароль" to "password",

        "url" to "url", "uri" to "url", "login_uri" to "url", "web site" to "url",
        "website" to "url", "site" to "url", "ссылка" to "url", "сайт" to "url",
        "адрес" to "url",

        "notes" to "notes", "note" to "notes", "comment" to "notes",
        "comments" to "notes", "заметки" to "notes", "примечания" to "notes",

        "created" to "created", "creation time" to "created",
        "modified" to "modified", "last modified" to "modified",
    )

    private fun field(e: Entry, name: String): String = when (name) {
        "title" -> e.title
        "login" -> e.login
        "password" -> e.password
        "url" -> e.url
        "notes" -> e.notes
        "created" -> e.created
        "modified" -> e.modified
        else -> ""
    }

    private fun setField(e: Entry, name: String, value: String) {
        when (name) {
            "title" -> e.title = value
            "login" -> e.login = value
            "password" -> e.password = value
            "url" -> e.url = value
            "created" -> e.created = value
            "modified" -> e.modified = value
            "notes" -> e.notes = value
        }
    }

    private fun csvCell(value: String): String =
        if (value.any { it == ',' || it == '"' || it == '\n' || it == '\r' })
            "\"" + value.replace("\"", "\"\"") + "\""
        else value

    fun exportCsv(entries: List<Entry>): String {
        val sb = StringBuilder()
        sb.append(COLUMNS.joinToString(",")).append("\r\n")
        for (e in entries) {
            if (e.deleted) continue
            sb.append(COLUMNS.joinToString(",") { csvCell(field(e, it)) }).append("\r\n")
        }
        return sb.toString()
    }

    fun exportJson(entries: List<Entry>): String {
        val arr = JSONArray()
        for (e in entries) {
            if (e.deleted) continue
            val o = JSONObject()
            COLUMNS.forEach { o.put(it, field(e, it)) }
            o.put("id", e.id)
            arr.put(o)
        }
        return JSONObject().apply {
            put("exported", Ts.now())
            put("entries", arr)
        }.toString(2)
    }

    /** Разбор строки CSV с учётом кавычек и переводов строк внутри ячеек. */
    fun parseCsvRows(text: String, delimiter: Char): List<List<String>> {
        val rows = ArrayList<List<String>>()
        var row = ArrayList<String>()
        val cell = StringBuilder()
        var quoted = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                quoted && c == '"' && i + 1 < text.length && text[i + 1] == '"' -> {
                    cell.append('"'); i++
                }
                c == '"' -> quoted = !quoted
                !quoted && c == delimiter -> { row.add(cell.toString()); cell.setLength(0) }
                !quoted && (c == '\n' || c == '\r') -> {
                    if (c == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    row.add(cell.toString()); cell.setLength(0)
                    rows.add(row); row = ArrayList()
                }
                else -> cell.append(c)
            }
            i++
        }
        if (cell.isNotEmpty() || row.isNotEmpty()) { row.add(cell.toString()); rows.add(row) }
        return rows.filter { r -> r.any { it.isNotBlank() } }
    }

    private fun pickDelimiter(head: String): Char {
        val counts = listOf(',', ';', '\t').map { d -> d to head.count { it == d } }
        val best = counts.maxByOrNull { it.second }!!
        return if (best.second == 0) ',' else best.first
    }

    private fun mapHeader(name: String): String? =
        ALIASES[name.trim().removePrefix("FEFF").lowercase()]

    fun parseCsv(raw: String): List<Entry> {
        val text = raw.removePrefix("FEFF")
        val firstLine = text.lineSequence().firstOrNull() ?: ""
        val rows = parseCsvRows(text, pickDelimiter(firstLine))
        if (rows.isEmpty()) throw BadImport("Файл пуст")

        val header = rows[0].map { mapHeader(it) }
        if (header.all { it == null })
            throw BadImport("В первой строке не найдено знакомых заголовков.\n" +
                    "Ожидаются столбцы вида: title, login, password, url, notes.")

        val out = ArrayList<Entry>()
        for (r in rows.drop(1)) {
            val e = Entry.fresh()
            e.title = ""
            header.forEachIndexed { i, f -> if (f != null && i < r.size) setField(e, f, r[i]) }
            if (e.title.isBlank() && e.login.isBlank() &&
                e.password.isBlank() && e.url.isBlank()) continue
            if (e.title.isBlank()) e.title = "(без названия)"
            if (e.created.isBlank()) e.created = Ts.now()
            if (e.modified.isBlank()) e.modified = Ts.now()
            out.add(e)
        }
        if (out.isEmpty()) throw BadImport("В файле не нашлось ни одной записи")
        return out
    }

    fun parseJson(raw: String): List<Entry> {
        val text = raw.removePrefix("FEFF").trim()
        val items = try {
            if (text.startsWith("[")) JSONArray(text)
            else JSONObject(text).optJSONArray("entries")
                ?: throw BadImport("Ожидался список записей в поле entries")
        } catch (e: BadImport) {
            throw e
        } catch (e: Exception) {
            throw BadImport("Не удалось разобрать JSON: ${e.message}")
        }

        val out = ArrayList<Entry>()
        for (i in 0 until items.length()) {
            val o = items.optJSONObject(i) ?: continue
            val e = Entry.fresh()
            e.title = ""
            // id из чужого файла не берём: он может столкнуться с нашим и
            // «слипнуться» с существующей записью при следующем слиянии.
            COLUMNS.forEach { f -> if (o.has(f)) setField(e, f, o.optString(f, "")) }
            if (e.title.isBlank() && e.login.isBlank() &&
                e.password.isBlank() && e.url.isBlank()) continue
            if (e.title.isBlank()) e.title = "(без названия)"
            if (e.created.isBlank()) e.created = Ts.now()
            if (e.modified.isBlank()) e.modified = Ts.now()
            out.add(e)
        }
        if (out.isEmpty()) throw BadImport("В файле не нашлось ни одной записи")
        return out
    }

    /** Читает файл, подбирая кодировку, и разбирает по содержимому. */
    fun parse(bytes: ByteArray, nameHint: String = ""): List<Entry> {
        var text: String? = null
        for (charset in listOf(Charsets.UTF_8, charset("windows-1251"),
                               charset("IBM866"), Charsets.ISO_8859_1)) {
            try {
                val decoded = String(bytes, charset)
                if (!decoded.contains('�')) { text = decoded; break }
            } catch (_: Exception) {
            }
        }
        val body = (text ?: String(bytes, Charsets.UTF_8)).removePrefix("FEFF")
        val looksJson = nameHint.lowercase().endsWith(".json") ||
                body.trimStart().startsWith("{") || body.trimStart().startsWith("[")
        return if (looksJson) parseJson(body) else parseCsv(body)
    }
}

// ---------------------------------------------------------------- слияние
object Merge {
    enum class Decision { LOCAL, INCOMING, BOTH }

    class Conflict(val local: Entry, val incoming: Entry) {
        val title: String
            get() = local.title.ifBlank { incoming.title.ifBlank { "(без названия)" } }

        val incomingIsNewer: Boolean get() = Ts.isNewer(incoming.modified, local.modified)

        val sameTimestamp: Boolean
            get() = Ts.sortKey(local.modified) == Ts.sortKey(incoming.modified)

        /** По умолчанию предлагаем более свежую сторону. */
        fun suggestion(): Decision = if (incomingIsNewer) Decision.INCOMING else Decision.LOCAL
    }

    class Stats(var added: Int = 0, var keptLocal: Int = 0,
                var tookIncoming: Int = 0, var keptBoth: Int = 0)

    class Plan(val toAdd: List<Entry>, val conflicts: List<Conflict>) {
        val isEmpty: Boolean get() = toAdd.isEmpty() && conflicts.isEmpty()
        fun suggestions(): List<Decision> = conflicts.map { it.suggestion() }
    }

    /**
     * Готовит план слияния.
     *
     * Повторяющиеся id ВНУТРИ входящего файла разводятся. Файл может быть
     * повреждён или собран чужой программой, и раньше две записи с одним id
     * просто добавлялись обе. Дальше они затеняли друг друга при каждой
     * синхронизации: правка на втором устройстве не доезжала никогда, и
     * понять почему было невозможно.
     */
    fun plan(local: List<Entry>, incoming: List<Entry>): Plan {
        val byId = HashMap<String, Entry>()
        local.forEach { if (it.id.isNotBlank()) byId[it.id] = it }

        val used = HashSet(byId.keys)
        val seenIncoming = HashSet<String>()
        val toAdd = ArrayList<Entry>()
        val conflicts = ArrayList<Conflict>()

        for (source in incoming) {
            if (source.id.isBlank()) continue
            var inc = source
            if (!seenIncoming.add(inc.id)) {
                inc = Entry.fromJson(inc.toJson())      // чужой объект не правим
                var fresh = Entry.newId()
                while (!used.add(fresh)) fresh = Entry.newId()
                inc.id = fresh
                seenIncoming.add(fresh)
            } else {
                used.add(inc.id)
            }

            val loc = byId[inc.id]
            if (loc == null) toAdd.add(inc)
            else if (!loc.contentEquals(inc)) conflicts.add(Conflict(loc, inc))
        }
        return Plan(toAdd, conflicts)
    }

    /**
     * Общая история двух версий записи, новые сверху, без повторов.
     *
     * dropped — пароль, который сейчас будет затёрт. Прежняя версия при выборе
     * «взять из файла» теряла локальный пароль бесследно: это был единственный
     * штатный путь, на котором пароль исчезал, при том что история паролей
     * существует ровно для таких случаев.
     */
    fun mergeHistories(primary: List<PastPassword>, secondary: List<PastPassword>,
                       dropped: String = ""): MutableList<PastPassword> {
        val out = ArrayList<PastPassword>()
        val seen = HashSet<String>()
        for (h in primary + secondary) {
            if (h.password.isEmpty() || !seen.add(h.password)) continue
            out.add(h)
        }
        if (dropped.isNotEmpty() && seen.add(dropped))
            out.add(PastPassword(dropped, Ts.now()))
        out.sortByDescending { Ts.sortKey(it.changed) }
        while (out.size > Entry.MAX_HISTORY) out.removeAt(out.size - 1)
        return out
    }

    fun apply(local: MutableList<Entry>, plan: Plan, decisions: List<Decision>): Stats {
        require(decisions.size == plan.conflicts.size) {
            "Число решений (${decisions.size}) не совпадает с числом конфликтов (${plan.conflicts.size})"
        }
        val st = Stats()
        val ids = local.mapTo(HashSet()) { it.id }

        for (inc in plan.toAdd) { local.add(inc); ids.add(inc.id); st.added++ }

        for (i in plan.conflicts.indices) {
            val c = plan.conflicts[i]
            when (decisions[i]) {
                Decision.LOCAL -> {
                    // Даже оставляя свою версию, забираем чужую историю: прошлые
                    // пароли с другого устройства пригодятся, а терять их незачем.
                    c.local.history = mergeHistories(c.local.history, c.incoming.history)
                    st.keptLocal++
                }
                Decision.INCOMING -> {
                    val dropped = if (c.local.password != c.incoming.password)
                        c.local.password else ""
                    val merged = mergeHistories(c.incoming.history, c.local.history, dropped)
                    c.local.copyContentFrom(c.incoming)
                    c.local.history = merged
                    st.tookIncoming++
                }
                Decision.BOTH -> {
                    val copy = Entry.fromJson(c.incoming.toJson())
                    var newId = Entry.newId()
                    while (!ids.add(newId)) newId = Entry.newId()
                    copy.id = newId
                    copy.title = (copy.title + " (копия)").trim()
                    copy.deleted = false
                    local.add(copy)
                    st.keptBoth++
                }
            }
        }
        return st
    }
}
