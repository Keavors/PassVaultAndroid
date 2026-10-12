package com.example.passvault

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.time.LocalDateTime

/**
 * JVM-тесты ядра. Идут без устройства и эмулятора: Core.kt намеренно не
 * обращается к android.*, поэтому проверяется обычным `gradlew test`.
 *
 * Самое важное здесь — тесты совместимости с ПК-версией и тест записи на
 * диск. Раньше ни то, ни другое не проверялось ничем.
 */
class CoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val pw get() = "мастер-фраза проверки".toCharArray()

    /**
     * Настоящие 256 МиБ Argon2id в юнит-тестах гонять незачем: проверяется
     * логика вокруг формата, а не стойкость KDF. Формат контейнера от
     * уменьшения параметров не меняется.
     */
    private fun fast() = Crypto.KdfParams.argon2id(timeCost = 1,
        memoryKib = 8 * 1024, parallelism = 1)

    @Before
    fun useFastKdf() {
        VaultRepo.upgradeParams = { fast() }
    }

    @After
    fun resetState() {
        VaultRepo.upgradeParams = { Crypto.KdfParams.default() }
        VaultRepo.lock()          // VaultRepo — синглтон, состояние течёт между тестами
    }

    private fun sampleJson(marker: String = "секрет"): String = JSONObject().apply {
        put("version", 1)
        put("entries", org.json.JSONArray().apply {
            put(JSONObject().apply {
                put("id", "a1")
                put("title", "Почта")
                put("login", "u@e.com")
                put("password", marker)
                put("url", "https://e.com")
                put("notes", "заметки ёЁ")
                put("created", "2026-01-01T10:00:00Z")
                put("modified", "2026-01-01T10:00:00Z")
            })
        })
        put("settings", JSONObject())
    }.toString()

    // ================================================================ крипта
    @Test
    fun roundtripPreservesCyrillic() {
        val json = sampleJson()
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        val blob = Crypto.encrypt(json, key, params)
        val op = Crypto.decrypt(blob, pw)
        assertEquals(json, op.json)
        assertEquals(20_000, op.params.iterations)
    }

    @Test
    fun wrongPasswordRejected() {
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        val blob = Crypto.encrypt(sampleJson(), key, params)
        for (bad in listOf("не та фраза", "", "МАСТЕР-ФРАЗА ПРОВЕРКИ")) {
            try {
                Crypto.decrypt(blob, bad.toCharArray())
                fail("файл открылся с неверным паролем: $bad")
            } catch (_: Crypto.WrongPassword) {
            }
        }
    }

    @Test
    fun tamperingDetected() {
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        val blob = Crypto.encrypt(sampleJson(), key, params)
        val bad = blob.copyOf()
        bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 0xFF).toByte()
        try {
            Crypto.decrypt(bad, pw)
            fail("подмена не замечена")
        } catch (_: Crypto.WrongPassword) {
        }
    }

    @Test
    fun absurdIterationsRejected() {
        // Заголовок с максимальным uint32 вешал приложение на много минут.
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        val blob = Crypto.encrypt(sampleJson(), key, params)
        val evil = blob.copyOf()
        for (i in 0 until 4) evil[8 + i] = 0xFF.toByte()
        try {
            Crypto.parse(evil)
            fail("абсурдное число итераций принято")
        } catch (e: Crypto.BadFormat) {
            assertTrue(e.message!!.contains("итераций"))
        }
    }

    @Test
    fun garbageRejected() {
        for (junk in listOf(ByteArray(0), "не хранилище".toByteArray())) {
            try {
                Crypto.parse(junk)
                fail("мусор принят за хранилище")
            } catch (_: Crypto.BadFormat) {
            }
        }
    }

    // Параметры уменьшены: настоящие 256 МиБ в юнит-тестах гонять незачем.
    private fun argon2Params() = Crypto.KdfParams(
        Crypto.KDF_ARGON2ID, Crypto.randomBytes(Crypto.SALT_LEN),
        timeCost = 1, memoryKib = 8 * 1024, parallelism = 1)

    @Test
    fun argon2RoundtripWorks() {
        val params = argon2Params()
        val key = Crypto.deriveKey(pw, params)
        val blob = Crypto.encrypt(sampleJson(), key, params)
        assertTrue(blob.copyOfRange(0, 8).contentEquals(Crypto.MAGIC_V2))

        val op = Crypto.decrypt(blob, pw)
        assertEquals(sampleJson(), op.json)
        assertEquals(Crypto.KDF_ARGON2ID, op.params.kdfId)
        assertEquals(1, op.params.timeCost)
        assertEquals(8 * 1024, op.params.memoryKib)
    }

    @Test
    fun argon2WrongPasswordRejected() {
        val params = argon2Params()
        val blob = Crypto.encrypt(sampleJson(), Crypto.deriveKey(pw, params), params)
        try {
            Crypto.decrypt(blob, "не та фраза".toCharArray())
            fail("файл открылся с неверным паролем")
        } catch (_: Crypto.WrongPassword) {
        }
    }

    @Test
    fun absurdArgon2MemoryRejected() {
        val params = argon2Params()
        val blob = Crypto.encrypt(sampleJson(), Crypto.deriveKey(pw, params), params)
        val evil = blob.copyOf()
        for (i in 0 until 4) evil[13 + i] = 0xFF.toByte()
        try {
            Crypto.parse(evil)
            fail("абсурдный объём памяти принят")
        } catch (e: Crypto.BadFormat) {
            assertTrue(e.message!!.contains("памяти"))
        }
    }

    @Test
    fun unknownKdfIdRejected() {
        val params = argon2Params()
        val blob = Crypto.encrypt(sampleJson(), Crypto.deriveKey(pw, params), params)
        val evil = blob.copyOf()
        evil[8] = 99
        try {
            Crypto.parse(evil)
            fail("неизвестный алгоритм принят")
        } catch (e: Crypto.BadFormat) {
            assertTrue(e.message!!.contains("алгоритм"))
        }
    }

    // ================================================================ время
    @Test
    fun parsesBothTimestampFormats() {
        assertNotNull(Ts.parse("2026-01-31T11:05:42Z"))
        assertNotNull(Ts.parse("2026-01-31 14:05"))        // старый формат
        assertNotNull(Ts.parse("2026-01-31T14:05:00+03:00"))
        assertNull(Ts.parse("не дата"))
        assertNull(Ts.parse(null))
    }

    @Test
    fun timezoneAwareComparison() {
        val msk = "2026-01-31T14:05:00+03:00"      // 11:05 UTC
        val utc = "2026-01-31T12:00:00Z"           // на 55 минут позже
        assertTrue(Ts.isNewer(utc, msk))
        assertFalse(Ts.isNewer(msk, utc))
    }

    @Test
    fun secondsResolution() {
        assertTrue(Ts.isNewer("2026-01-31T11:05:43Z", "2026-01-31T11:05:42Z"))
    }

    // ================================================================ записи
    @Test
    fun unknownFieldsSurviveRewrite() {
        // Без этого телефон при первом же сохранении выбрасывал бы всё, что
        // добавила более новая версия на ПК.
        val src = JSONObject("""
            {"id":"x1","title":"Т","login":"l","password":"p","notes":"n",
             "created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z",
             "totp":"JBSWY3DPEHPK3PXP","tags":["работа","важное"]}
        """.trimIndent())
        val e = Entry.fromJson(src)
        val out = e.toJson()
        assertEquals("JBSWY3DPEHPK3PXP", out.optString("totp"))
        assertEquals(2, out.getJSONArray("tags").length())
        assertEquals("Т", out.optString("title"))
    }

    @Test
    fun historyRoundTrips() {
        val e = Entry.fresh()
        e.password = "второй"
        e.pushHistory("первый")
        val back = Entry.fromJson(e.toJson())
        assertEquals(1, back.history.size)
        assertEquals("первый", back.history[0].password)
    }

    @Test
    fun historyCapped() {
        val e = Entry.fresh()
        for (i in 0 until Entry.MAX_HISTORY + 5) e.pushHistory("пароль-$i")
        assertEquals(Entry.MAX_HISTORY, e.history.size)
        assertEquals("пароль-${Entry.MAX_HISTORY + 4}", e.history[0].password)
    }

    @Test
    fun deletedFlagOmittedWhenFalse() {
        val e = Entry.fresh()
        assertFalse(e.toJson().has("deleted"))
        e.deleted = true
        assertTrue(e.toJson().getBoolean("deleted"))
    }

    // ================================================================ генератор
    @Test
    fun generatorRespectsConstraints() {
        val o = Gen.defaults()
        o.put("exact_mode", true); o.put("exact_len", 20)
        o.put("required_chars", "Ж#"); o.put("excluded_chars", "abcdef")
        o.put("no_ambiguous", true)
        repeat(120) {
            val (p, _) = Gen.generate(o)
            assertEquals(20, p.length)
            assertTrue(p.contains("Ж"))
            assertTrue(p.contains("#"))
            for (c in "abcdef") assertFalse(p.contains(c))
            for (c in Gen.AMBIGUOUS) assertFalse(p.contains(c))
        }
    }

    @Test
    fun emptySymbolSetErrors() {
        val o = Gen.defaults()
        o.put("use_symbols", true); o.put("symbols", "")
        try {
            Gen.generate(o)
            fail("пустой набор спецсимволов принят молча")
        } catch (e: Gen.BadOptions) {
            assertTrue(e.message!!.contains("пуст"))
        }
    }

    @Test
    fun entropyEstimateIsConservative() {
        val o = Gen.defaults()
        val plain = Gen.estimateBits(o, 20, 70)
        o.put("required_chars", "ABCDE")
        assertTrue(Gen.estimateBits(o, 20, 70) < plain)
    }

    // ================================================================ запись
    @Test
    fun writeKeepsPreviousVersion() {
        val dir = tmp.newFolder()
        val target = File(dir, "vault.pmv")
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)

        val b1 = Crypto.encrypt(sampleJson("первый"), key, params)
        VaultIO.writeAtomic(target, b1, key)
        assertTrue(target.exists())
        assertFalse(File(dir, "vault.pmv.prev").exists())

        val b2 = Crypto.encrypt(sampleJson("второй"), key, params)
        VaultIO.writeAtomic(target, b2, key)
        assertTrue(File(dir, "vault.pmv.prev").exists())
        assertTrue(Crypto.decryptWithKey(target.readBytes(), key).contains("второй"))
        assertTrue(Crypto.decryptWithKey(File(dir, "vault.pmv.prev").readBytes(), key)
            .contains("первый"))
    }

    @Test
    fun corruptedWriteIsRejectedAndOriginalSurvives() {
        val dir = tmp.newFolder()
        val target = File(dir, "vault.pmv")
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)

        val good = Crypto.encrypt(sampleJson("ценное"), key, params)
        VaultIO.writeAtomic(target, good, key)

        val garbage = Crypto.MAGIC + byteArrayOf(0, 0, 0x4E, 0x20) + ByteArray(200)
        try {
            VaultIO.writeAtomic(target, garbage, key)
            fail("битая запись принята")
        } catch (_: VaultIO.WriteFailed) {
        }
        assertTrue(Crypto.decryptWithKey(target.readBytes(), key).contains("ценное"))
        assertFalse(File(dir, "vault.pmv.tmp").exists())
    }

    @Test
    fun recoveryCandidatesFound() {
        val dir = tmp.newFolder()
        val target = File(dir, "vault.pmv")
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        VaultIO.writeAtomic(target, Crypto.encrypt(sampleJson("1"), key, params), key)
        VaultIO.writeAtomic(target, Crypto.encrypt(sampleJson("2"), key, params), key)

        assertTrue(target.delete())
        val found = VaultIO.recoveryCandidates(dir)
        assertTrue("не найдено ни одного кандидата", found.isNotEmpty())
    }

    @Test
    fun recoveryIgnoresForeignFiles() {
        val dir = tmp.newFolder()
        File(dir, "vault.pmv.prev").writeText("это не хранилище")
        assertTrue(VaultIO.recoveryCandidates(dir).isEmpty())
    }

    // ================================================================ снимки
    private fun fabricate(dir: File, at: LocalDateTime, tag: String? = null) {
        val d = Backups.dir(dir).apply { mkdirs() }
        val stamp = at.format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
        File(d, "snap-$stamp${if (tag != null) "-$tag" else ""}.pmv")
            .writeBytes(Crypto.MAGIC + ByteArray(60))
    }

    @Test
    fun gfsRetentionKeepsLongHistory() {
        val dir = tmp.newFolder()
        val now = LocalDateTime.of(2026, 8, 7, 12, 0, 0)
        var t = now
        repeat(3 * 24 * 6) { fabricate(dir, t); t = t.minusMinutes(10) }
        for (d in 4..400) fabricate(dir, now.minusDays(d.toLong()))

        val before = Backups.list(dir).size
        Backups.prune(dir)
        val kept = Backups.list(dir)

        assertTrue(kept.size < before)
        assertTrue(kept.size <= Backups.KEEP_RECENT + Backups.KEEP_HOURLY +
                Backups.KEEP_DAILY + Backups.KEEP_MONTHLY)
        val oldest = kept.minByOrNull { it.at }!!.at
        assertTrue("должна оставаться история за месяцы",
            java.time.Duration.between(oldest, now).toDays() > 300)
    }

    @Test
    fun eventSnapshotsKeptSeparately() {
        val dir = tmp.newFolder()
        val now = LocalDateTime.of(2026, 8, 7, 12, 0, 0)
        for (d in 1..5) fabricate(dir, now.minusDays(d.toLong()), "premerge")
        for (d in 1..200) fabricate(dir, now.minusDays(d.toLong()))
        Backups.prune(dir)
        assertEquals(5, Backups.list(dir).count { it.isEvent })
    }

    // ================================================================ слияние
    private fun entry(id: String, title: String, pwd: String, modified: String,
                      deleted: Boolean = false) = Entry.fromJson(JSONObject().apply {
        put("id", id); put("title", title); put("password", pwd)
        put("login", ""); put("notes", ""); put("url", "")
        put("created", "2026-01-01T00:00:00Z"); put("modified", modified)
        if (deleted) put("deleted", true)
    })

    @Test
    fun mergePlanAndApply() {
        val local = mutableListOf(
            entry("same", "Одинаковая", "pw", "2026-01-02T10:00:00Z"),
            entry("conf", "Почта", "OLD", "2026-01-03T10:00:00Z"),
            entry("onlyLocal", "Только тут", "1", "2026-01-01T10:00:00Z"),
        )
        val incoming = listOf(
            entry("same", "Одинаковая", "pw", "2026-01-04T11:00:00Z"),
            entry("conf", "Почта", "NEW", "2026-01-04T10:00:00Z"),
            entry("onlyIncoming", "С ПК", "2", "2026-01-06T10:00:00Z"),
        )
        val plan = Merge.plan(local, incoming)
        assertEquals(listOf("onlyIncoming"), plan.toAdd.map { it.id })
        assertEquals(listOf("conf"), plan.conflicts.map { it.local.id })

        // входящая версия свежее — предлагаем её
        assertEquals(Merge.Decision.INCOMING, plan.conflicts[0].suggestion())

        val st = Merge.apply(local, plan, plan.suggestions())
        assertEquals(1, st.added)
        assertEquals(1, st.tookIncoming)
        assertEquals("NEW", local.first { it.id == "conf" }.password)
    }

    @Test
    fun secondMergePassIsClean() {
        val local = mutableListOf(entry("a", "А", "1", "2026-01-01T00:00:00Z"))
        val incoming = listOf(entry("a", "А", "2", "2026-01-02T00:00:00Z"))
        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, plan.suggestions())
        val again = Merge.plan(local, local.map { Entry.fromJson(it.toJson()) })
        assertTrue(again.isEmpty)
    }

    @Test
    fun keepBothMakesDistinctCopy() {
        val local = mutableListOf(entry("a", "А", "1", "2026-01-01T00:00:00Z"))
        val incoming = listOf(entry("a", "А", "2", "2026-01-02T00:00:00Z"))
        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, listOf(Merge.Decision.BOTH))
        assertEquals(2, local.size)
        assertTrue(local[1].id != local[0].id)
        assertTrue(local[1].title.endsWith("(копия)"))
        assertEquals("2", local[1].password)
    }

    @Test
    fun deletionPropagates() {
        val local = mutableListOf(entry("a", "А", "1", "2026-01-01T00:00:00Z"))
        val incoming = listOf(entry("a", "А", "1", "2026-01-05T00:00:00Z", deleted = true))
        val plan = Merge.plan(local, incoming)
        assertEquals(1, plan.conflicts.size)
        Merge.apply(local, plan, plan.suggestions())
        assertTrue("удаление должно перенестись", local[0].deleted)
    }

    // ====================================== история паролей при слиянии
    @Test
    fun takingIncomingSavesLocalPasswordToHistory() {
        // Единственный штатный путь, на котором пароль раньше пропадал бесследно.
        val local = mutableListOf(entry("a", "Почта", "ЛОКАЛЬНЫЙ", "2026-01-01T00:00:00Z"))
        val incoming = listOf(entry("a", "Почта", "ИЗ_ФАЙЛА", "2026-01-02T00:00:00Z"))
        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, listOf(Merge.Decision.INCOMING))

        assertEquals("ИЗ_ФАЙЛА", local[0].password)
        assertTrue("прежний пароль обязан попасть в историю",
            local[0].history.any { it.password == "ЛОКАЛЬНЫЙ" })
    }

    @Test
    fun historiesAreMergedNotDropped() {
        val local = mutableListOf(entry("a", "П", "L", "2026-01-01T00:00:00Z"))
        local[0].history.add(PastPassword("старый-локальный", "2025-12-01T00:00:00Z"))
        val incoming = listOf(entry("a", "П", "I", "2026-01-02T00:00:00Z"))
        incoming[0].history.add(PastPassword("старый-входящий", "2025-11-01T00:00:00Z"))

        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, listOf(Merge.Decision.INCOMING))

        val passwords = local[0].history.map { it.password }
        assertTrue(passwords.contains("старый-локальный"))
        assertTrue(passwords.contains("старый-входящий"))
        assertTrue(passwords.contains("L"))
    }

    @Test
    fun keepingLocalStillAbsorbsIncomingHistory() {
        val local = mutableListOf(entry("a", "П", "L", "2026-01-02T00:00:00Z"))
        val incoming = listOf(entry("a", "П", "I", "2026-01-01T00:00:00Z"))
        incoming[0].history.add(PastPassword("чужой-прошлый", "2025-11-01T00:00:00Z"))

        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, listOf(Merge.Decision.LOCAL))

        assertEquals("L", local[0].password)
        assertTrue(local[0].history.any { it.password == "чужой-прошлый" })
    }

    @Test
    fun mergedHistoryStaysCapped() {
        val local = mutableListOf(entry("a", "П", "L", "2026-01-01T00:00:00Z"))
        val incoming = listOf(entry("a", "П", "I", "2026-01-02T00:00:00Z"))
        for (i in 0 until 10) {
            local[0].history.add(PastPassword("a$i", "2025-01-%02dT00:00:00Z".format(i + 1)))
            incoming[0].history.add(PastPassword("b$i", "2024-01-%02dT00:00:00Z".format(i + 1)))
        }
        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, listOf(Merge.Decision.INCOMING))
        assertTrue(local[0].history.size <= Entry.MAX_HISTORY)
    }

    @Test
    fun copyContentDoesNotShareUnknownFields() {
        val src = Entry.fromJson(JSONObject("""{"id":"a","totp":"SECRET"}"""))
        val dst = Entry.fresh()
        dst.copyContentFrom(src)
        // Правка «будущего» поля в одной записи не должна менять другую.
        val mutated = Entry.fromJson(src.toJson().put("totp", "ДРУГОЕ"))
        assertEquals("SECRET", dst.toJson().optString("totp"))
        assertEquals("ДРУГОЕ", mutated.toJson().optString("totp"))
    }

    // ====================================== снимки из байтов
    @Test
    fun snapshotIsWrittenFromGivenBytes() {
        val dir = tmp.newFolder()
        val blob = Crypto.MAGIC + ByteArray(60) { 0x11 }
        val snap = Backups.write(dir, blob, "premerge")
        assertNotNull(snap)
        assertTrue(snap!!.file.readBytes().contentEquals(blob))
        assertTrue(snap.isEvent)
        assertTrue(snap.label().contains("перед слиянием"))
    }

    @Test
    fun twoEventsInOneSecondDoNotCollide() {
        val dir = tmp.newFolder()
        val now = LocalDateTime.of(2026, 8, 8, 12, 0, 0)
        val a = Backups.write(dir, Crypto.MAGIC + ByteArray(60), "premerge", now)
        val b = Backups.write(dir, Crypto.MAGIC + ByteArray(60) { 1 }, "premerge", now)
        assertNotNull(a); assertNotNull(b)
        assertTrue(a!!.file.path != b!!.file.path)
        assertEquals(2, Backups.list(dir).size)
    }

    @Test
    fun eventSnapshotDoesNotSwallowTheNextAutomaticOne() {
        // Прежняя версия считала отпечаток по памяти, а файл копировала с диска;
        // после событийного снимка ближайшее сохранение решало, что менять нечего.
        val dir = tmp.newFolder()
        val t0 = 1_700_000_000_000L
        val minute = 60_000L

        VaultRepo.create(dir, pw, fast())
        VaultRepo.entries.add(Entry.fresh().also { it.title = "Первая" })
        VaultRepo.save(dir, t0)

        val before = Backups.list(dir).size
        VaultRepo.snapshot(dir, "premerge", t0 + minute)
        VaultRepo.entries.add(Entry.fresh().also { it.title = "Вторая" })
        VaultRepo.save(dir, t0 + 10 * minute)

        assertTrue("после событийного снимка изменения обязаны сниматься",
            Backups.list(dir).size > before + 1)
        VaultRepo.lock()
    }

    @Test
    fun eventSnapshotCapturesUnsavedEdits() {
        val dir = tmp.newFolder()
        VaultRepo.create(dir, pw, fast())
        VaultRepo.entries.add(Entry.fresh().also { it.title = "До слияния" })
        // save() намеренно не вызываем: снимок обязан снять то, что на экране.
        val snap = VaultRepo.snapshot(dir, "premerge")
        assertNotNull(snap)
        val json = Crypto.decrypt(snap!!.file.readBytes(), pw).json
        assertTrue(json.contains("До слияния"))
        VaultRepo.lock()
    }

    // ====================================== задержка после неверных паролей
    @Test
    fun throttleGivesThreeAttemptsThenPauses() {
        val dir = tmp.newFolder()
        val now = 1_000_000L
        assertEquals(0, Throttle.recordFailure(dir, now))
        assertEquals(0, Throttle.recordFailure(dir, now))
        assertEquals(5, Throttle.recordFailure(dir, now))
        assertTrue(Throttle.isLocked(dir, now))
        assertFalse(Throttle.isLocked(dir, now + 6_000))
    }

    @Test
    fun throttleDelayGrows() {
        val dir = tmp.newFolder()
        var now = 1_000_000L
        val delays = ArrayList<Int>()
        repeat(15) {
            val d = Throttle.recordFailure(dir, now)
            if (d > 0) { delays.add(d); now += d * 1000L + 1000L }
        }
        assertEquals(listOf(5, 30, 120, 600), delays.take(4))
    }

    @Test
    fun throttleSurvivesClockRollback() {
        val dir = tmp.newFolder()
        val now = 1_000_000L
        repeat(3) { Throttle.recordFailure(dir, now) }
        assertTrue("перевод часов назад не должен снимать паузу",
            Throttle.isLocked(dir, now - 10_000_000L))
    }

    @Test
    fun successResetsThrottle() {
        val dir = tmp.newFolder()
        val now = 1_000_000L
        repeat(3) { Throttle.recordFailure(dir, now) }
        Throttle.recordSuccess(dir)
        assertEquals(0, Throttle.failures(dir))
        assertFalse(Throttle.isLocked(dir, now))
    }

    // ====================================== единственный формат записи
    @Test
    fun defaultParamsAreArgon2() {
        assertFalse(Crypto.KdfParams.default().isLegacy)
        assertFalse(Crypto.KdfParams.default().needsUpgrade)
    }

    @Test
    fun newVaultIsArgon2() {
        // Раньше create() звал pbkdf2(), и каждое новое хранилище на телефоне
        // получало слабейший из двух вариантов.
        val dir = tmp.newFolder()
        VaultRepo.create(dir, pw)
        val head = VaultRepo.file(dir).readBytes().copyOfRange(0, 8)
        assertTrue(head.contentEquals(Crypto.MAGIC_V2))
        VaultRepo.lock()
    }

    @Test
    fun legacyVaultIsUpgradedOnOpen() {
        val dir = tmp.newFolder()
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        VaultIO.writeAtomic(VaultRepo.file(dir),
            Crypto.encrypt(sampleJson("ценное"), key, params), key)

        val notes = VaultRepo.open(dir, pw)

        assertFalse("формат не обновился", VaultRepo.formatDescription().contains("PBKDF2"))
        val head = VaultRepo.file(dir).readBytes().copyOfRange(0, 8)
        assertTrue("файл на диске обязан стать PMVAULT2", head.contentEquals(Crypto.MAGIC_V2))
        assertTrue("пользователю не сказали о переводе: $notes",
            notes.any { it.contains("Argon2id") })
        assertEquals("ценное", VaultRepo.entries[0].password)
        VaultRepo.lock()

        // И тем же паролем открывается снова.
        VaultRepo.open(dir, pw)
        assertEquals("ценное", VaultRepo.entries[0].password)
        VaultRepo.lock()
    }

    @Test
    fun upgradeKeepsReadableCopyInTheOldFormat() {
        val dir = tmp.newFolder()
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        VaultIO.writeAtomic(VaultRepo.file(dir),
            Crypto.encrypt(sampleJson("до переезда"), key, params), key)

        VaultRepo.open(dir, pw)
        val snaps = Backups.list(dir).filter { it.tag == "preformat" }
        assertTrue("снимок перед переездом не сделан", snaps.isNotEmpty())

        val blob = snaps[0].file.readBytes()
        assertTrue("копия обязана остаться в старом формате",
            blob.copyOfRange(0, 8).contentEquals(Crypto.MAGIC))
        assertTrue(Crypto.decrypt(blob, pw).json.contains("до переезда"))
        VaultRepo.lock()
    }

    @Test
    fun upgradeHappensOnlyOnce() {
        val dir = tmp.newFolder()
        val params = Crypto.KdfParams.pbkdf2(20_000)
        val key = Crypto.deriveKey(pw, params)
        VaultIO.writeAtomic(VaultRepo.file(dir),
            Crypto.encrypt(sampleJson(), key, params), key)

        VaultRepo.open(dir, pw)
        VaultRepo.lock()
        val notes = VaultRepo.open(dir, pw)
        assertFalse("переезд повторился на уже обновлённом хранилище",
            notes.any { it.contains("Argon2id") })
        assertEquals(1, Backups.list(dir).count { it.tag == "preformat" })
        VaultRepo.lock()
    }

    @Test
    fun firstOpenFillsTheEmptyArchive() {
        val dir = tmp.newFolder()
        VaultRepo.create(dir, pw, fast())
        VaultRepo.lock()
        Backups.list(dir).forEach { it.file.delete() }
        assertTrue(Backups.list(dir).isEmpty())

        VaultRepo.open(dir, pw)
        assertTrue("после открытия в архиве обязан быть снимок",
            Backups.list(dir).isNotEmpty())
        VaultRepo.lock()
    }

    // ====================================== незнакомые ключи корня
    @Test
    fun unknownRootKeysSurviveRewrite() {
        val dir = tmp.newFolder()
        VaultRepo.create(dir, pw, fast())
        val json = JSONObject(VaultRepo.toJsonString())
        json.put("future_root", "значение из будущего")
        VaultRepo.lock()

        val params = Crypto.KdfParams.argon2id(timeCost = 1, memoryKib = 8 * 1024,
            parallelism = 1)
        val key = Crypto.deriveKey(pw, params)
        VaultIO.writeAtomic(VaultRepo.file(dir),
            Crypto.encrypt(json.toString(), key, params), key)

        VaultRepo.open(dir, pw)
        val back = JSONObject(VaultRepo.toJsonString())
        assertEquals("значение из будущего", back.optString("future_root"))
        VaultRepo.lock()
    }

    // ====================================== дубликаты id при слиянии
    @Test
    fun duplicateIdsInsideIncomingFileAreSplit() {
        val local = mutableListOf<Entry>()
        val incoming = listOf(
            entry("dup", "Первая", "1", "2026-01-01T00:00:00Z"),
            entry("dup", "Вторая", "2", "2026-01-02T00:00:00Z"),
        )
        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, plan.suggestions())

        assertEquals(2, local.size)
        assertEquals("в хранилище оказались две записи с одним id",
            2, local.map { it.id }.toSet().size)
        assertEquals(setOf("Первая", "Вторая"), local.map { it.title }.toSet())
    }

    @Test
    fun duplicateIdDoesNotCollideWithLocal() {
        val local = mutableListOf(entry("dup", "Своя", "L", "2026-01-01T00:00:00Z"))
        val incoming = listOf(
            entry("dup", "Чужая", "I", "2026-01-02T00:00:00Z"),
            entry("dup", "Чужая вторая", "I2", "2026-01-03T00:00:00Z"),
        )
        val plan = Merge.plan(local, incoming)
        Merge.apply(local, plan, plan.suggestions())
        assertEquals(local.size, local.map { it.id }.toSet().size)
    }

    // ====================================== CSV и JSON
    @Test
    fun csvRoundtripSurvivesSeparatorsAndNewlines() {
        val e = Entry.fresh()
        e.title = "Почта, личная"
        e.login = "u@e.com"
        e.password = "па\"роль;1"
        e.url = "https://e.com"
        e.notes = "первая строка\nвторая строка"

        val back = Portable.parseCsv(Portable.exportCsv(listOf(e)))
        assertEquals(1, back.size)
        assertEquals("Почта, личная", back[0].title)
        assertEquals("па\"роль;1", back[0].password)
        assertTrue(back[0].notes.contains("вторая строка"))
    }

    @Test
    fun jsonRoundtrip() {
        val e = Entry.fresh()
        e.title = "Банк ёЁ"
        e.password = "секрет"
        val back = Portable.parseJson(Portable.exportJson(listOf(e)))
        assertEquals("Банк ёЁ", back[0].title)
        assertEquals("секрет", back[0].password)
    }

    @Test
    fun deletedEntriesAreNotExported() {
        val gone = Entry.fresh().also { it.title = "Удалённая"; it.deleted = true }
        val live = Entry.fresh().also { it.title = "Живая"; it.password = "p" }
        assertEquals(1, Portable.parseCsv(Portable.exportCsv(listOf(gone, live))).size)
    }

    @Test
    fun bitwardenAndKeepassHeadersAreUnderstood() {
        val bitwarden = "name,login_username,login_password,login_uri\n" +
                "Почта,u@e.com,секрет,https://e.com\n"
        val keepass = "Account,Login Name,Password,Web Site\n" +
                "Банк,ivan,пароль,https://bank.example\n"
        assertEquals("Почта", Portable.parseCsv(bitwarden)[0].title)
        assertEquals("ivan", Portable.parseCsv(keepass)[0].login)
    }

    @Test
    fun semicolonDelimiterIsDetected() {
        val csv = "title;login;password\nПочта;u;секрет\n"
        assertEquals("секрет", Portable.parseCsv(csv)[0].password)
    }

    @Test
    fun unknownHeadersRejectedWithClearMessage() {
        try {
            Portable.parseCsv("колонка1,колонка2\nа,б\n")
            fail("файл без знакомых заголовков принят")
        } catch (e: Portable.BadImport) {
            assertTrue(e.message!!.contains("заголовк"))
        }
    }

    @Test
    fun foreignIdsAreNotReused() {
        // id из чужого файла может столкнуться с нашим и «слипнуться» с
        // существующей записью при следующем слиянии.
        val json = """{"entries":[{"id":"a1","title":"Чужая","password":"p"}]}"""
        assertFalse(Portable.parseJson(json)[0].id == "a1")
    }

    @Test
    fun importOnlyAdds() {
        val dir = tmp.newFolder()
        VaultRepo.create(dir, pw, fast())
        VaultRepo.entries.add(entry("mine", "Своя", "L", "2026-01-01T00:00:00Z"))
        val added = VaultRepo.addEntries(
            listOf(entry("mine", "Чужая с тем же id", "I", "2026-01-02T00:00:00Z")))
        assertEquals(1, added)
        assertEquals(2, VaultRepo.entries.size)
        assertEquals(2, VaultRepo.entries.map { it.id }.toSet().size)
        assertEquals("Своя", VaultRepo.entries.first { it.id == "mine" }.title)
        VaultRepo.lock()
    }

    @Test
    fun wrongPasswordOnOpenCountsTowardsLockout() {
        val dir = tmp.newFolder()
        VaultRepo.create(dir, pw, fast())
        VaultRepo.lock()
        repeat(2) {
            try {
                VaultRepo.open(dir, "не тот".toCharArray())
                fail("файл открылся неверным паролем")
            } catch (_: Crypto.WrongPassword) {
            }
        }
        assertEquals(2, Throttle.failures(dir))
        VaultRepo.open(dir, pw)
        assertEquals(0, Throttle.failures(dir))
        VaultRepo.lock()
    }
}
