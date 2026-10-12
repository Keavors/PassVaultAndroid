package com.example.passvault

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity() {

    private lateinit var panelUnlock: View
    private lateinit var panelList: View
    private lateinit var tvFile: TextView
    private lateinit var tvError: TextView
    private lateinit var etPw1: EditText
    private lateinit var etPw2: EditText
    private lateinit var btnUnlock: Button
    private lateinit var etSearch: EditText
    private lateinit var list: ListView

    private val shown = ArrayList<Entry>()
    private lateinit var adapter: ArrayAdapter<Entry>

    // Предложение восстановиться показываем один раз за запуск, иначе оно
    // всплывало бы при каждом возврате на экран.
    private var recoveryOffered = false

    /**
     * Тик автоблокировки.
     *
     * Раньше срок проверялся ТОЛЬКО в onResume. Открытое хранилище, лежащее на
     * экране списка, не блокировалось никогда, сколько бы времени ни прошло:
     * возвращаться на экран было неоткуда. ПК-версия тикает раз в 10 секунд —
     * здесь теперь так же.
     */
    private val ticker = Handler(Looper.getMainLooper())
    private val autoLockTick = object : Runnable {
        override fun run() {
            if (VaultRepo.expired()) {
                VaultRepo.lock()
                updatePanels()
                toast("Заблокировано после бездействия")
            }
            ticker.postDelayed(this, AUTOLOCK_TICK_MS)
        }
    }

    private companion object {
        const val AUTOLOCK_TICK_MS = 10_000L
    }

    // экспорт: системный диалог «куда сохранить» (SAF) — работает без разрешений
    private val exportLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            if (uri != null && VaultRepo.unlocked) {
                try {
                    contentResolver.openOutputStream(uri, "w")!!.use { it.write(VaultRepo.exportBlob()) }
                    toast("Копия сохранена")
                } catch (e: Exception) {
                    toast("Не удалось сохранить: ${e.message}")
                }
            }
        }

    // импорт: системный диалог выбора файла (SAF)
    private val importLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                try {
                    val blob = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                    // Чаще всего файл под тем же паролем — тогда не спрашиваем.
                    val json = VaultRepo.tryOpenWithCurrentKey(blob)
                    if (json != null) {
                        startMerge(json, "импортированный файл", "premerge")
                    } else {
                        askFilePassword { pw ->
                            inBackground("Расшифровываю файл…",
                                { Crypto.decrypt(blob, pw).json }) { result ->
                                result.onSuccess {
                                    startMerge(it, "импортированный файл", "premerge")
                                }.onFailure { e -> toast(e.message ?: "Ошибка") }
                            }
                        }
                    }
                } catch (e: Exception) {
                    toast("Не удалось прочитать файл: ${e.message}")
                }
            }
        }

    // Экспорт БЕЗ ШИФРОВАНИЯ. Раньше этого на телефоне не было вовсе: данные
    // доставались только самим приложением и только в его формате, то есть
    // пользователь был к нему привязан.
    private var plainFormat = "csv"
    private val exportPlainLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            if (uri == null || !VaultRepo.unlocked) return@registerForActivityResult
            try {
                val text = if (plainFormat == "csv")
                    Portable.exportCsv(VaultRepo.entries)
                else Portable.exportJson(VaultRepo.entries)
                contentResolver.openOutputStream(uri, "w")!!.use {
                    // utf-8 с BOM — иначе Excel превращает кириллицу в кашу.
                    it.write(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()))
                    it.write(text.toByteArray(Charsets.UTF_8))
                }
                toast("Экспортировано БЕЗ ШИФРОВАНИЯ. Удали файл после переноса.")
            } catch (e: Exception) {
                toast("Не удалось сохранить: ${e.message}")
            }
        }

    private val importPlainLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null || !VaultRepo.unlocked) return@registerForActivityResult
            val entries = try {
                val bytes = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                Portable.parse(bytes, uri.lastPathSegment ?: "")
            } catch (e: Exception) {
                toast(e.message ?: "Не удалось разобрать файл"); return@registerForActivityResult
            }
            AlertDialog.Builder(this)
                .setTitle("Импорт")
                .setMessage("Найдено записей: ${entries.size}. Добавить?\n\n" +
                        "Импорт только добавляет, существующие записи не трогает.")
                .setPositiveButton("Добавить") { _, _ ->
                    if (!Dialogs.snapshotOrReport(this, filesDir, "preimport")) return@setPositiveButton
                    val added = VaultRepo.addEntries(entries)
                    Dialogs.saveOrReport(this, filesDir)
                    refreshList()
                    toast("Добавлено записей: $added")
                }
                .setNegativeButton("Отмена", null)
                .show()
        }

    private fun exportPlain(format: String) {
        plainFormat = format
        AlertDialog.Builder(this)
            .setTitle("Экспорт без шифрования")
            .setMessage("Файл будет сохранён БЕЗ ШИФРОВАНИЯ — пароли открытым " +
                    "текстом.\nПродолжить?")
            .setPositiveButton("Продолжить") { _, _ ->
                exportPlainLauncher.launch("passvault-export.$format")
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    /**
     * Открыть другой файл хранилища.
     *
     * На ПК это переключение рабочего файла; здесь хранилище обязано лежать во
     * внутренней памяти приложения, поэтому выбранный файл становится текущим,
     * а прежний уходит в архив снимков — вернуть его можно оттуда.
     */
    private val openVaultLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) return@registerForActivityResult
            val blob = try {
                contentResolver.openInputStream(uri)!!.use { it.readBytes() }
            } catch (e: Exception) {
                toast("Не удалось прочитать файл: ${e.message}"); return@registerForActivityResult
            }
            try {
                Crypto.parse(blob)
            } catch (e: Crypto.BadFormat) {
                toast(e.message ?: "Не файл хранилища"); return@registerForActivityResult
            }
            askFilePassword { pw ->
                inBackground("Расшифровываю файл…", { Crypto.decrypt(blob, pw) }) { result ->
                    result.onSuccess { opened -> replaceVaultWith(blob, pw, opened) }
                        .onFailure { e -> toast(e.message ?: "Не удалось открыть") }
                }
            }
        }

    private fun replaceVaultWith(blob: ByteArray, pw: CharArray, opened: Crypto.Opened) {
        val hasCurrent = VaultRepo.file(filesDir).exists()
        val message = if (hasCurrent)
            "Открыть этот файл как текущее хранилище?\nПрежнее уйдёт в резервные копии."
        else "Открыть этот файл как текущее хранилище?"

        AlertDialog.Builder(this)
            .setTitle("Открыть другой файл")
            .setMessage(message)
            .setPositiveButton("Открыть") { _, _ ->
                inBackground("Открываю хранилище…", {
                    if (VaultRepo.unlocked) VaultRepo.snapshot(filesDir, "prerestore")
                    else if (hasCurrent) {
                        Backups.write(filesDir, VaultRepo.file(filesDir).readBytes(),
                            "prerestore")
                    }
                    VaultIO.writeAtomic(VaultRepo.file(filesDir), blob, opened.key)
                    VaultRepo.lock()
                    VaultRepo.open(filesDir, pw)
                }) { result ->
                    result.onSuccess { notes ->
                        updatePanels(); refreshList()
                        notes.lastOrNull()?.let { toast(it) }
                    }.onFailure { e -> toast("Не удалось открыть: ${e.message}") }
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // запрет скриншотов и предпросмотра в «недавних приложениях»
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_main)

        val root = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        panelUnlock = findViewById(R.id.panel_unlock)
        panelList = findViewById(R.id.panel_list)
        tvFile = findViewById(R.id.tv_file)
        tvError = findViewById(R.id.tv_error)
        etPw1 = findViewById(R.id.et_pw1)
        etPw2 = findViewById(R.id.et_pw2)
        btnUnlock = findViewById(R.id.btn_unlock)
        etSearch = findViewById(R.id.et_search)
        list = findViewById(R.id.lv_entries)

        adapter = object : ArrayAdapter<Entry>(this,
            android.R.layout.simple_list_item_2, android.R.id.text1, shown) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val v = super.getView(position, convertView, parent)
                val e = shown[position]
                v.findViewById<TextView>(android.R.id.text1).text =
                    e.title.ifBlank { "(без названия)" }
                v.findViewById<TextView>(android.R.id.text2).text =
                    listOf(e.login, "изм. ${Ts.display(e.modified)}")
                        .filter { it.isNotBlank() }.joinToString("  ·  ")
                return v
            }
        }
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ ->
            startActivity(Intent(this, EntryActivity::class.java).putExtra("id", shown[pos].id))
        }
        list.setOnItemLongClickListener { _, _, pos, _ -> confirmDelete(shown[pos]); true }

        etSearch.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { refreshList() }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })

        btnUnlock.setOnClickListener { unlockOrCreate() }
        findViewById<Button>(R.id.btn_new).setOnClickListener {
            val e = Entry.fresh()
            VaultRepo.entries.add(e)
            Dialogs.saveOrReport(this, filesDir)
            startActivity(Intent(this, EntryActivity::class.java).putExtra("id", e.id))
        }
        findViewById<Button>(R.id.btn_menu).setOnClickListener { showMenu(it) }
        findViewById<Button>(R.id.btn_open_other).setOnClickListener {
            openVaultLauncher.launch(arrayOf("*/*"))
        }
    }

    override fun onResume() {
        super.onResume()
        if (VaultRepo.expired()) VaultRepo.lock()
        VaultRepo.touch()
        updatePanels()
        refreshList()
        ticker.removeCallbacks(autoLockTick)
        ticker.postDelayed(autoLockTick, AUTOLOCK_TICK_MS)
    }

    override fun onPause() {
        ticker.removeCallbacks(autoLockTick)
        super.onPause()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        VaultRepo.touch()
    }

    private fun updatePanels() {
        val exists = VaultRepo.file(filesDir).exists()
        if (VaultRepo.unlocked) {
            panelUnlock.visibility = View.GONE
            panelList.visibility = View.VISIBLE
            etSearch.requestFocus()
            val imm = getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager
            imm.showSoftInput(etSearch, InputMethodManager.SHOW_IMPLICIT)
        } else {
            panelUnlock.visibility = View.VISIBLE
            panelList.visibility = View.GONE
            etPw1.setText(""); etPw2.setText(""); tvError.text = ""
            etPw2.visibility = if (exists) View.GONE else View.VISIBLE
            btnUnlock.text = if (exists) "Открыть" else "Создать хранилище"
            tvFile.text = if (exists) "" else "Хранилище ещё не создано"
            if (!exists && !recoveryOffered) {
                recoveryOffered = true
                offerRecovery()
            }
        }
    }

    /** Пауза после неверных паролей — видимая, а не молчаливая. */
    private fun startCountdown() {
        val left = Throttle.remaining(filesDir)
        if (left <= 0) {
            btnUnlock.isEnabled = true
            etPw1.isEnabled = true
            tvError.text = ""
            return
        }
        btnUnlock.isEnabled = false
        etPw1.isEnabled = false
        tvError.text = "Слишком много неверных попыток. Подожди ${Throttle.humanDelay(left)}"
        etPw1.postDelayed({ startCountdown() }, 1000)
    }

    /**
     * Долгая работа в фоне с окошком «подожди».
     *
     * Argon2id честно занимает 256 МиБ и несколько секунд. На главном потоке
     * это гарантированный ANR — Android убьёт приложение за неотзывчивость
     * ровно в тот момент, когда человек вводит мастер-пароль. Прежний код
     * считал KDF прямо в обработчике нажатия; с PBKDF2 это ещё как-то
     * проскакивало, с Argon2id — уже нет.
     */
    private fun <T> inBackground(message: String, work: () -> T,
                                 onDone: (Result<T>) -> Unit) {
        val box = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            setPadding(64, 48, 64, 48)
            addView(ProgressBar(this@MainActivity))
            addView(TextView(this@MainActivity).apply {
                text = message
                setPadding(32, 0, 0, 0)
            })
        }
        val dlg = AlertDialog.Builder(this).setView(box).setCancelable(false).create()
        dlg.show()

        Thread {
            val result = runCatching(work)
            runOnUiThread {
                if (!isFinishing && !isDestroyed) dlg.dismiss()
                onDone(result)
            }
        }.start()
    }

    private fun unlockOrCreate() {
        val exists = VaultRepo.file(filesDir).exists()
        val p1 = etPw1.text.toString()
        if (p1.isEmpty()) return
        if (exists) {
            if (Throttle.isLocked(filesDir)) { startCountdown(); return }
            inBackground("Расшифровываю хранилище…",
                { VaultRepo.open(filesDir, p1.toCharArray()) }) { result ->
                result.onSuccess { notes ->
                    updatePanels(); refreshList()
                    // Показываем последнее: перевод на Argon2id важнее прочего.
                    notes.lastOrNull()?.let { toast(it) }
                }.onFailure { e ->
                    when (e) {
                        is Crypto.WrongPassword -> {
                            if (Throttle.remaining(filesDir) > 0) startCountdown()
                            else tvError.text = "${e.message}\nПопыток до паузы: " +
                                    "${Throttle.attemptsLeft(filesDir)}"
                        }
                        else -> tvError.text = "Не удалось открыть файл: ${e.message}"
                    }
                }
            }
        } else {
            val p2 = etPw2.text.toString()
            if (p1 != p2) { tvError.text = "Пароли не совпадают"; return }
            val doCreate = {
                inBackground("Создаю хранилище…",
                    { VaultRepo.create(filesDir, p1.toCharArray()) }) { result ->
                    result.onSuccess { updatePanels(); refreshList() }
                        // Раньше ошибка записи здесь не ловилась вовсе и
                        // роняла приложение при первом же запуске на
                        // заполненном телефоне.
                        .onFailure { e ->
                            VaultRepo.lock()
                            tvError.text = "Не удалось создать хранилище: ${e.message}"
                        }
                }
            }
            if (p1.length < 12) {
                AlertDialog.Builder(this)
                    .setMessage("Мастер-пароль короче 12 символов — его проще подобрать перебором.\nВсё равно использовать?")
                    .setPositiveButton("Да") { _, _ -> doCreate() }
                    .setNegativeButton("Нет", null)
                    .show()
            } else doCreate()
        }
    }

    private fun refreshList() {
        if (!VaultRepo.unlocked) return
        val q = etSearch.text.toString().lowercase().trim()
        shown.clear()
        VaultRepo.entries.asSequence()
            .filter { !it.deleted }
            .filter {
                q.isEmpty() || (it.title + " " + it.login + " " + it.url + " " + it.notes)
                    .lowercase().contains(q)
            }
            .sortedBy { it.title.lowercase() }
            .forEach { shown.add(it) }
        adapter.notifyDataSetChanged()
    }

    private fun confirmDelete(e: Entry) {
        AlertDialog.Builder(this)
            .setTitle("Удалить запись")
            .setMessage("Удалить «${e.title.ifBlank { "(без названия)" }}»?")
            .setPositiveButton("Удалить") { _, _ ->
                VaultRepo.softDelete(e)
                Dialogs.saveOrReport(this, filesDir)
                refreshList()
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    // ------------------------------------------------------------ меню
    private fun showMenu(anchor: View) {
        val pm = PopupMenu(this, anchor)
        val trashCount = VaultRepo.trashed().size
        var order = 0
        pm.menu.add(0, 1, order++, "Импорт и слияние (файл с ПК)")
        pm.menu.add(0, 2, order++, "Экспорт копии (для ПК)")
        pm.menu.add(0, 3, order++, if (trashCount > 0) "Корзина ($trashCount)" else "Корзина")
        pm.menu.add(0, 4, order++, "Резервные копии")
        pm.menu.add(0, 5, order++, "Генератор паролей")
        pm.menu.add(0, 12, order++, "Экспорт в CSV (без шифрования)")
        pm.menu.add(0, 13, order++, "Экспорт в JSON (без шифрования)")
        pm.menu.add(0, 14, order++, "Импорт из CSV/JSON")
        pm.menu.add(0, 6, order++, "Сменить мастер-пароль")
        pm.menu.add(0, 7, order++, "Настройки")
        pm.menu.add(0, 8, order++, "Очистить старые удалённые")
        pm.menu.add(0, 9, order++, "Открыть другой файл")
        pm.menu.add(0, 10, order++, "Заблокировать")
        pm.menu.add(0, 11, order, "О программе")
        pm.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                1 -> importLauncher.launch(arrayOf("*/*"))
                2 -> exportLauncher.launch(VaultRepo.FILE_NAME)
                3 -> Dialogs.trash(this) { refreshList() }
                4 -> Dialogs.backups(this) { snap -> restoreFromSnapshot(snap) }
                5 -> Dialogs.generator(this, null)
                6 -> changePassword()
                7 -> Dialogs.settings(this)
                8 -> purgeTombstones()
                9 -> openVaultLauncher.launch(arrayOf("*/*"))
                10 -> { VaultRepo.lock(); updatePanels() }
                11 -> about()
                12 -> exportPlain("csv")
                13 -> exportPlain("json")
                14 -> importPlainLauncher.launch(arrayOf("*/*"))
            }
            true
        }
        pm.show()
    }

    private fun askFilePassword(onOk: (CharArray) -> Unit) {
        val et = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Мастер-пароль файла"
        }
        AlertDialog.Builder(this)
            .setTitle("Слияние")
            .setMessage("Мастер-пароль файла:")
            .setView(et)
            .setPositiveButton("OK") { _, _ -> onOk(et.text.toString().toCharArray()) }
            .setNegativeButton("Отмена", null)
            .show()
    }

    // ------------------------------------------------------------ слияние
    /**
     * Слияние с разбором расхождений. Тем же путём идёт восстановление из
     * снимка: копия подаётся как «входящий» файл, поэтому вернуть удалённую
     * запись можно, не потеряв добавленные позже.
     */
    private fun startMerge(incomingJson: String, source: String, tag: String) {
        val incoming = try {
            VaultRepo.parseEntries(incomingJson)
        } catch (e: Exception) {
            toast("Не удалось разобрать файл: ${e.message}")
            return
        }
        val plan = Merge.plan(VaultRepo.entries, incoming)
        if (plan.isEmpty) {
            AlertDialog.Builder(this)
                .setTitle("Слияние")
                .setMessage("Различий не найдено — всё уже совпадает.")
                .setPositiveButton("OK", null)
                .show()
            return
        }

        fun finish(decisions: List<Merge.Decision>) {
            // Снимок перед слиянием обязателен, и если он не сделан — слияние
            // отменяется целиком. Раньше исключение отсюда не ловилось вообще
            // и роняло приложение посреди операции над данными.
            if (!Dialogs.snapshotOrReport(this, filesDir, tag)) return
            val st = Merge.apply(VaultRepo.entries, plan, decisions)
            Dialogs.saveOrReport(this, filesDir)
            refreshList()
            AlertDialog.Builder(this)
                .setTitle("Слияние завершено")
                .setMessage("Добавлено: ${st.added}\n" +
                        "Расхождений: ${plan.conflicts.size}\n" +
                        "   с телефона: ${st.keptLocal}\n" +
                        "   из файла: ${st.tookIncoming}\n" +
                        "   обе версии: ${st.keptBoth}")
                .setPositiveButton("OK", null)
                .show()
        }

        Dialogs.mergePreview(this, plan, source) { mode ->
            if (mode == null) { toast("Слияние отменено — ничего не изменено"); return@mergePreview }

            val decisions = plan.suggestions().toMutableList()
            // Спрашиваем только про то, где «самое свежее» определить нельзя,
            // либо про всё подряд, если пользователь выбрал разбор по одному.
            val ask = if (mode == "auto")
                plan.conflicts.indices.filter { plan.conflicts[it].sameTimestamp }
            else
                plan.conflicts.indices.toList()

            fun next(n: Int) {
                if (n >= ask.size) { finish(decisions); return }
                val idx = ask[n]
                Dialogs.conflict(this, plan.conflicts[idx], n + 1, ask.size) { d, applyAll ->
                    if (d == null) {
                        toast("Слияние отменено — ничего не изменено")
                        return@conflict
                    }
                    decisions[idx] = d
                    if (applyAll) {
                        for (k in n + 1 until ask.size) decisions[ask[k]] = d
                        finish(decisions)
                    } else next(n + 1)
                }
            }
            next(0)
        }
    }

    private fun restoreFromSnapshot(snap: Backups.Snapshot) {
        val blob = try {
            snap.file.readBytes()
        } catch (e: Exception) {
            toast("Не удалось прочитать снимок: ${e.message}"); return
        }
        val json = VaultRepo.tryOpenWithCurrentKey(blob)
        if (json != null) {
            startMerge(json, "снимок от ${snap.label()}", "prerestore")
            return
        }
        // Снимок сделан до смены мастер-пароля — он зашифрован прежним.
        askFilePassword { pw ->
            inBackground("Расшифровываю снимок…",
                { Crypto.decrypt(blob, pw).json }) { result ->
                result.onSuccess {
                    startMerge(it, "снимок от ${snap.label()}", "prerestore")
                }.onFailure { e -> toast(e.message ?: "Не удалось открыть снимок") }
            }
        }
    }

    private fun purgeTombstones() {
        val doomed = VaultRepo.purgeableTombstones()
        if (doomed.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Очистка")
                .setMessage("Удалённых записей старше ${VaultRepo.TOMBSTONE_TTL_DAYS} дней нет.")
                .setPositiveButton("OK", null)
                .show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Очистка")
            .setMessage("Стереть ${doomed.size} записей старше " +
                    "${VaultRepo.TOMBSTONE_TTL_DAYS} дней? Отменить будет нельзя.")
            .setPositiveButton("Стереть") { _, _ ->
                if (!Dialogs.snapshotOrReport(this, filesDir, "prepurge")) return@setPositiveButton
                val n = VaultRepo.purgeTombstones()
                Dialogs.saveOrReport(this, filesDir)
                refreshList()
                toast("Вычищено записей: $n")
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    // ------------------------------------------------------------ прочее
    private fun changePassword() {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 16, 48, 0)
        }
        fun pwField(hintText: String) = EditText(this).apply {
            hint = hintText
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val cur = pwField("Текущий пароль")
        val n1 = pwField("Новый пароль")
        val n2 = pwField("Новый ещё раз")
        layout.addView(cur); layout.addView(n1); layout.addView(n2)
        AlertDialog.Builder(this)
            .setTitle("Смена мастер-пароля")
            .setView(layout)
            .setPositiveButton("Применить") { _, _ ->
                if (n1.text.toString() != n2.text.toString()) {
                    toast("Новые пароли не совпадают"); return@setPositiveButton
                }
                if (n1.text.isEmpty()) return@setPositiveButton
                val current = cur.text.toString().toCharArray()
                val fresh = n1.text.toString().toCharArray()
                // Здесь Argon2id считается ДВАЖДЫ: проверка текущего пароля и
                // ключ для нового. На главном потоке это верный ANR.
                inBackground("Меняю мастер-пароль…",
                    { VaultRepo.changePassword(filesDir, current, fresh) }) { result ->
                    result.onSuccess { ok ->
                        toast(if (ok) "Мастер-пароль изменён" else "Текущий пароль неверен")
                    }.onFailure { e -> toast("Пароль НЕ изменён: ${e.message}") }
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    /**
     * Формат берётся у открытого файла, а не из строковой константы.
     * Раньше здесь было захардкожено «PBKDF2, 600 000 итераций, PMVAULT1»,
     * и окно врало про любой файл, который этому не соответствовал.
     */
    private fun about() {
        val snaps = Backups.list(filesDir)
        val size = Backups.totalSize(filesDir)
        AlertDialog.Builder(this)
            .setTitle("О программе")
            .setMessage("PassVault ${BuildConfig.VERSION_NAME}\n\n" +
                    "${VaultRepo.file(filesDir).absolutePath}\n" +
                    "AES-256-GCM\n" +
                    "${VaultRepo.formatDescription()}\n\n" +
                    "Снимков: ${snaps.size} (${size / 1024} КБ)")
            .setPositiveButton("OK", null)
            .show()
    }

    /**
     * Хранилище пропало, но копии уцелели. Без этого экрана приложение
     * предлагало бы создать новое пустое хранилище — прямой путь к потере.
     */
    private fun offerRecovery() {
        val candidates = VaultIO.recoveryCandidates(filesDir)
        if (candidates.isEmpty()) return
        val labels = candidates.map {
            "${Ts.display(java.time.Instant.ofEpochMilli(it.modified).toString())}\n" +
                    "${it.note}  ·  ${it.file.length()} Б"
        }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle("Хранилище не найдено")
            .setMessage("Выбери копию для восстановления:")
            .setItems(labels) { _, which ->
                val c = candidates[which]
                try {
                    c.file.copyTo(VaultRepo.file(filesDir), overwrite = true)
                    toast("Хранилище восстановлено. Введи мастер-пароль, которым была " +
                            "зашифрована эта копия.")
                } catch (e: Exception) {
                    toast("Не удалось восстановить: ${e.message}")
                }
                updatePanels()
            }
            .setNegativeButton("Создать новое пустое", null)
            .show()
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
}
