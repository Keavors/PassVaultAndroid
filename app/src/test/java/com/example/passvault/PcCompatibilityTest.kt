package com.example.passvault

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Совместимость с версией для ПК — проверяется на настоящих файлах.
 *
 * Эталоны в app/src/test/resources созданы кодом ПК-версии
 * (tools/make_android_fixture.py). Если форматы разойдутся, эти тесты упадут
 * ЗДЕСЬ, а не съедят данные при синхронизации на телефоне.
 *
 *   pc_vault_argon2.pmv — PMVAULT2, единственный формат, который ПК пишет
 *   pc_vault.pmv        — PMVAULT1, старый формат, который ПК обязан читать
 *
 * Пересоздать эталоны:  python tools/make_android_fixture.py
 */
class PcCompatibilityTest {

    private val password = "тестовая мастер-фраза".toCharArray()

    private fun resource(name: String): ByteArray {
        val stream = javaClass.classLoader!!.getResourceAsStream(name)
        assertNotNull("эталон $name не найден в ресурсах тестов", stream)
        return stream!!.use { it.readBytes() }
    }

    private fun fixture(): ByteArray = resource("pc_vault.pmv")

    @Test
    fun opensFileWrittenByPc() {
        val op = Crypto.decrypt(fixture(), password)
        val root = JSONObject(op.json)
        assertEquals(1, root.getInt("version"))
        assertEquals(20_000, op.params.iterations)
        assertEquals(3, root.getJSONArray("entries").length())
    }

    @Test
    fun readsAllFieldsIncludingNewOnes() {
        val entries = VaultRepo.parseEntries(Crypto.decrypt(fixture(), password).json)
        val e = entries.first { it.id == "aaaa1111bbbb2222" }
        assertEquals("Почта Ёлка", e.title)
        assertEquals("user@example.com", e.login)
        assertEquals("пАроль Йц1!", e.password)
        assertEquals("https://mail.example.com", e.url)
        assertTrue(e.notes.contains("вторая строка"))
        assertEquals(2, e.history.size)
        assertEquals("прошлый-1", e.history[0].password)
    }

    @Test
    fun understandsLegacyTimestampsFromOldVersions() {
        val entries = VaultRepo.parseEntries(Crypto.decrypt(fixture(), password).json)
        val legacy = entries.first { it.id == "cccc3333dddd4444" }
        assertNotNull("старый формат «2026-01-02 11:30» должен разбираться",
            Ts.parse(legacy.modified))
        val modern = entries.first { it.id == "aaaa1111bbbb2222" }
        assertTrue("метка ISO должна быть новее старой",
            Ts.isNewer(modern.modified, legacy.modified))
    }

    @Test
    fun tombstoneFromPcIsRecognised() {
        val entries = VaultRepo.parseEntries(Crypto.decrypt(fixture(), password).json)
        val gone = entries.first { it.id == "eeee5555ffff6666" }
        assertTrue(gone.deleted)
        assertEquals(2, entries.count { !it.deleted })
    }

    @Test
    fun unknownPcFieldSurvivesPhoneRewrite() {
        // Главный тест совместимости. Телефон не знает поля future_field, но
        // обязан вернуть его в файл нетронутым — иначе каждая синхронизация
        // отгрызала бы по куску данных.
        val entries = VaultRepo.parseEntries(Crypto.decrypt(fixture(), password).json)
        val e = entries.first { it.id == "aaaa1111bbbb2222" }

        val rewritten = e.toJson()
        assertTrue("поле future_field потеряно при перезаписи",
            rewritten.has("future_field"))
        val kept = rewritten.getJSONObject("future_field")
        assertTrue(kept.getBoolean("kept"))
        assertEquals(3, kept.getJSONArray("nested").length())
    }

    @Test
    fun rewrittenFileIsReadableAgain() {
        val op = Crypto.decrypt(fixture(), password)
        val entries = VaultRepo.parseEntries(op.json)

        val root = JSONObject().apply {
            put("version", 1)
            put("entries", org.json.JSONArray().apply { entries.forEach { put(it.toJson()) } })
            put("settings", JSONObject(op.json).getJSONObject("settings"))
        }
        val blob = Crypto.encrypt(root.toString(), op.key, op.params)

        val back = Crypto.decrypt(blob, password)
        val backRoot = JSONObject(back.json)
        assertEquals(1, backRoot.getInt("version"))
        assertEquals(3, backRoot.getJSONArray("entries").length())
        assertEquals(7, backRoot.getJSONObject("settings")
            .getJSONObject("app").getInt("autolock_minutes"))
    }

    /**
     * Старый файл с ПК открывается — и это должно работать вечно.
     * Выброси разбор PMVAULT1, и каждое существующее хранилище, каждый .prev
     * и каждый снимок в архиве превратятся в нечитаемый мусор.
     */
    @Test
    fun legacyPbkdf2FileFromPcStillOpens() {
        val blob = fixture()
        assertTrue(blob.copyOfRange(0, 8).contentEquals(Crypto.MAGIC))
        val op = Crypto.decrypt(blob, password)
        assertEquals(Crypto.KDF_PBKDF2, op.params.kdfId)
        assertTrue(op.params.needsUpgrade)
        assertEquals(3, JSONObject(op.json).getJSONArray("entries").length())
    }

    @Test
    fun argon2FileNeedsNoUpgrade() {
        val op = Crypto.decrypt(argon2Fixture(), password)
        assertFalse(op.params.needsUpgrade)
    }

    /**
     * Пишет файл силами Android-кода, чтобы ПК-версия его прочитала.
     *
     * Совместимость проверяется в обе стороны: этот файл забирает тест
     * tests/test_android_interop.py в проекте ПК. Так расхождение форматов
     * всплывает на сборке, а не при синхронизации у пользователя.
     *
     * Формат — PMVAULT2: телефон, как и ПК, пишет только его.
     */
    @Test
    fun writesFileForPcToRead() {
        val e = Entry.fresh()
        e.title = "Запись с телефона"
        e.login = "phone@example.com"
        e.password = "пароль с телефона Ж1!"
        e.url = "https://phone.example.com"
        e.notes = "заметка ёЁ\nвторая строка"
        e.pushHistory("прежний-с-телефона")

        val deleted = Entry.fresh()
        deleted.title = "Удалено на телефоне"
        deleted.deleted = true

        val root = JSONObject().apply {
            put("version", 1)
            put("entries", org.json.JSONArray().apply { put(e.toJson()); put(deleted.toJson()) })
            put("settings", JSONObject().apply {
                put("generator", Gen.defaults())
                put("app", JSONObject().apply { put("autolock_minutes", 9) })
            })
        }

        // Параметры уменьшены: в тестах настоящие 256 МиБ гонять незачем,
        // формат контейнера от этого не меняется.
        val params = Crypto.KdfParams.argon2id(timeCost = 1, memoryKib = 8 * 1024,
            parallelism = 1)
        val key = Crypto.deriveKey(password, params)
        val blob = Crypto.encrypt(root.toString(), key, params)
        assertTrue("телефон обязан писать PMVAULT2",
            blob.copyOfRange(0, 8).contentEquals(Crypto.MAGIC_V2))

        val out = java.io.File("build/interop").apply { mkdirs() }
            .resolve("android_vault.pmv")
        out.writeBytes(blob)

        // Убеждаемся, что сами же читаем записанное.
        val back = Crypto.decrypt(out.readBytes(), password)
        assertEquals(2, JSONObject(back.json).getJSONArray("entries").length())
    }

    // Сохранение незнакомых ключей КОРНЯ файла проверяется честным путём — через
    // VaultRepo.open на настоящем файле — в CoreTest.unknownRootKeysSurviveRewrite.

    private fun argon2Fixture(): ByteArray = resource("pc_vault_argon2.pmv")

    /** Файл PMVAULT2 с ПК обязан открываться — тем же паролем и со всеми полями. */
    @Test
    fun opensArgon2FileFromPc() {
        val blob = argon2Fixture()
        assertTrue(blob.copyOfRange(0, 8).contentEquals(Crypto.MAGIC_V2))

        val op = Crypto.decrypt(blob, password)
        assertEquals(Crypto.KDF_ARGON2ID, op.params.kdfId)
        val root = JSONObject(op.json)
        assertEquals(3, root.getJSONArray("entries").length())

        val entries = VaultRepo.parseEntries(op.json)
        val e = entries.first { it.id == "aaaa1111bbbb2222" }
        assertEquals("Почта Ёлка", e.title)
        assertEquals("пАроль Йц1!", e.password)
    }

    @Test
    fun argon2FileRejectsWrongPassword() {
        try {
            Crypto.decrypt(argon2Fixture(), "не та фраза".toCharArray())
            fail("PMVAULT2 открылся неверным паролем")
        } catch (_: Crypto.WrongPassword) {
        }
    }

    /** Формат чужого файла не меняется при перезаписи телефоном. */
    @Test
    fun argon2FileStaysArgon2WhenRewritten() {
        val op = Crypto.decrypt(argon2Fixture(), password)
        val blob = Crypto.encrypt(op.json, op.key, op.params)
        assertTrue(blob.copyOfRange(0, 8).contentEquals(Crypto.MAGIC_V2))

        val back = Crypto.decrypt(blob, password)
        assertEquals(op.params.timeCost, back.params.timeCost)
        assertEquals(op.params.memoryKib, back.params.memoryKib)
        assertEquals(op.params.parallelism, back.params.parallelism)
        assertEquals(3, JSONObject(back.json).getJSONArray("entries").length())
    }

    @Test
    fun generatorSettingsFromPcAreHonoured() {
        val op = Crypto.decrypt(fixture(), password)
        val settings = JSONObject(op.json).getJSONObject("settings")
        VaultRepo.settings = settings
        val g = VaultRepo.genSettings()
        assertEquals(18, g.getInt("exact_len"))
        assertTrue(g.getBoolean("no_ambiguous"))
        assertTrue("недостающие ключи должны дополняться значениями по умолчанию",
            g.has("use_lower"))
        VaultRepo.settings = JSONObject()
    }
}
