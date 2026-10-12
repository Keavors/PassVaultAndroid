package com.example.passvault

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Build
import android.os.PersistableBundle
import android.view.LayoutInflater
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.json.JSONObject
import java.io.File

object Dialogs {

    fun toast(activity: Activity, msg: String) =
        Toast.makeText(activity, msg, Toast.LENGTH_LONG).show()

    private val clipboardTimer = android.os.Handler(android.os.Looper.getMainLooper())

    /**
     * Копирование с пометкой «чувствительное» — Android не покажет предпросмотр.
     *
     * И с будильником на стирание: пароль не должен лежать в буфере вечно.
     * Перед стиранием проверяем, что там всё ещё наш пароль — за эти секунды
     * человек мог скопировать что-то своё, и стирать чужое нельзя.
     */
    fun copySecret(activity: Activity, text: String) {
        if (text.isEmpty()) return
        val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("password", text)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        cm.setPrimaryClip(clip)

        val seconds = VaultRepo.appSettings().optInt("clipboard_seconds", 30)
        clipboardTimer.removeCallbacksAndMessages(null)
        if (seconds <= 0) return
        clipboardTimer.postDelayed({
            try {
                val clip0 = cm.primaryClip
                // itemCount проверяем обязательно: getItemAt(0) на пустом
                // буфере бросает исключение, а мы тут в отложенной задаче.
                val current = if (clip0 != null && clip0.itemCount > 0)
                    clip0.getItemAt(0).coerceToText(activity)?.toString() else null
                if (current == text) cm.setPrimaryClip(ClipData.newPlainText("", ""))
            } catch (_: Exception) {
            }
        }, seconds * 1000L)
    }

    // ------------------------------------------------------------ настройки
    /**
     * Настройки приложения. Раньше их можно было менять только на ПК, хотя
     * автоблокировка работала и здесь — телефон читал чужое значение и молчал.
     */
    fun settings(activity: Activity) {
        val app = VaultRepo.appSettings()
        val layout = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 0)
        }

        fun numberField(label: String, value: Int): EditText {
            layout.addView(TextView(activity).apply { text = label })
            val et = EditText(activity).apply {
                inputType = android.text.InputType.TYPE_CLASS_NUMBER
                setText(value.toString())
            }
            layout.addView(et)
            return et
        }

        val lock = numberField("Автоблокировка при бездействии, минут (1–180):",
            app.optInt("autolock_minutes", 5))
        val clip = numberField("Очищать буфер обмена через, секунд (0 — не очищать):",
            app.optInt("clipboard_seconds", 30))
        layout.addView(TextView(activity).apply {
            // Обещать больше, чем можем, нельзя.
            text = "Скопированный пароль может остаться в системной истории " +
                    "буфера обмена — её приложение очистить не может."
            alpha = 0.6f
        })

        AlertDialog.Builder(activity)
            .setTitle("Настройки")
            .setView(ScrollView(activity).apply { addView(layout) })
            .setPositiveButton("Сохранить") { _, _ ->
                val l = lock.text.toString().toIntOrNull() ?: 5
                val c = clip.text.toString().toIntOrNull() ?: 30
                app.put("autolock_minutes", l.coerceIn(1, 180))
                app.put("clipboard_seconds", c.coerceIn(0, 600))
                saveOrReport(activity, activity.filesDir)
                toast(activity, "Настройки сохранены")
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun humanSize(n: Long): String = when {
        n < 1024 -> "$n Б"
        n < 1024 * 1024 -> "%.1f КБ".format(n / 1024.0)
        else -> "%.1f МБ".format(n / 1024.0 / 1024.0)
    }

    /** Сохранение с показом ошибки: молча терять правки недопустимо. */
    fun saveOrReport(activity: Activity, dir: File): Boolean = try {
        VaultRepo.save(dir)
        true
    } catch (e: Exception) {
        AlertDialog.Builder(activity)
            .setTitle("Не удалось сохранить")
            .setMessage(e.message ?: "Неизвестная ошибка записи")
            .setPositiveButton("OK", null)
            .show()
        false
    }

    /**
     * Снимок перед опасной операцией. False — операцию делать нельзя.
     *
     * Раньше VaultRepo.snapshot вызывался голым, без обработки: ошибка записи
     * (кончилось место, отвалилась память) роняла приложение прямо посреди
     * слияния или чистки. ПК-версия в этом месте показывает ошибку и отменяет
     * операцию — здесь теперь так же.
     */
    fun snapshotOrReport(activity: Activity, dir: File, tag: String?): Boolean = try {
        VaultRepo.snapshot(dir, tag)
        true
    } catch (e: Exception) {
        AlertDialog.Builder(activity)
            .setTitle("Резервная копия")
            .setMessage("Не удалось сделать снимок перед операцией, операция " +
                    "отменена:\n${e.message}")
            .setPositiveButton("OK", null)
            .show()
        false
    }

    // ------------------------------------------------------------ генератор
    fun generator(activity: Activity, onUse: ((String) -> Unit)?) {
        val v = LayoutInflater.from(activity).inflate(R.layout.dialog_generator, null)
        val s = VaultRepo.genSettings()

        val cbLower = v.findViewById<CheckBox>(R.id.cb_lower)
        val cbUpper = v.findViewById<CheckBox>(R.id.cb_upper)
        val cbDigits = v.findViewById<CheckBox>(R.id.cb_digits)
        val cbSymbols = v.findViewById<CheckBox>(R.id.cb_symbols)
        val etSymbols = v.findViewById<EditText>(R.id.et_symbols)
        val cbRequire = v.findViewById<CheckBox>(R.id.cb_require_each)
        val cbNoAmb = v.findViewById<CheckBox>(R.id.cb_no_ambiguous)
        val rbExact = v.findViewById<RadioButton>(R.id.rb_exact)
        val rbRange = v.findViewById<RadioButton>(R.id.rb_range)
        val etExact = v.findViewById<EditText>(R.id.et_exact)
        val etMin = v.findViewById<EditText>(R.id.et_min)
        val etMax = v.findViewById<EditText>(R.id.et_max)
        val etReq = v.findViewById<EditText>(R.id.et_required)
        val etExcl = v.findViewById<EditText>(R.id.et_excluded)
        val tvResult = v.findViewById<TextView>(R.id.tv_result)
        val tvBits = v.findViewById<TextView>(R.id.tv_bits)

        cbLower.isChecked = s.optBoolean("use_lower", true)
        cbUpper.isChecked = s.optBoolean("use_upper", true)
        cbDigits.isChecked = s.optBoolean("use_digits", true)
        cbSymbols.isChecked = s.optBoolean("use_symbols", true)
        etSymbols.setText(s.optString("symbols", Gen.DEFAULT_SYMBOLS))
        cbRequire.isChecked = s.optBoolean("require_each", true)
        cbNoAmb.isChecked = s.optBoolean("no_ambiguous", false)
        rbExact.isChecked = s.optBoolean("exact_mode", true)
        rbRange.isChecked = !rbExact.isChecked
        etExact.setText(s.optInt("exact_len", 16).toString())
        etMin.setText(s.optInt("min_len", 12).toString())
        etMax.setText(s.optInt("max_len", 20).toString())
        etReq.setText(s.optString("required_chars"))
        etExcl.setText(s.optString("excluded_chars"))

        fun syncLen() {
            etExact.isEnabled = rbExact.isChecked
            etMin.isEnabled = rbRange.isChecked
            etMax.isEnabled = rbRange.isChecked
        }
        rbExact.setOnCheckedChangeListener { _, _ -> syncLen() }
        rbRange.setOnCheckedChangeListener { _, _ -> syncLen() }
        syncLen()

        fun collect(): JSONObject = JSONObject().apply {
            put("use_lower", cbLower.isChecked)
            put("use_upper", cbUpper.isChecked)
            put("use_digits", cbDigits.isChecked)
            put("use_symbols", cbSymbols.isChecked)
            put("symbols", etSymbols.text.toString())
            put("require_each", cbRequire.isChecked)
            put("exact_mode", rbExact.isChecked)
            put("exact_len", etExact.text.toString().toIntOrNull() ?: 16)
            put("min_len", etMin.text.toString().toIntOrNull() ?: 12)
            put("max_len", etMax.text.toString().toIntOrNull() ?: 20)
            put("required_chars", etReq.text.toString())
            put("excluded_chars", etExcl.text.toString())
            put("no_ambiguous", cbNoAmb.isChecked)
        }

        val builder = AlertDialog.Builder(activity)
            .setTitle("Генератор паролей")
            .setView(v)
            .setNegativeButton("Закрыть", null)
        if (onUse != null) builder.setPositiveButton("Вставить в запись", null)
        val dlg = builder.create()
        dlg.show()

        v.findViewById<Button>(R.id.btn_generate).setOnClickListener {
            try {
                val opts = collect()
                val (pwd, poolSize) = Gen.generate(opts)
                tvResult.text = pwd
                val bits = Gen.estimateBits(opts, pwd.length, poolSize)
                tvBits.text = "Стойкость: не менее ≈%.0f бит — %s  (алфавит %d)"
                    .format(bits, Gen.rate(bits), poolSize)
                VaultRepo.settings.put("generator", opts)
                saveOrReport(activity, activity.filesDir)
            } catch (e: Gen.BadOptions) {
                toast(activity, e.message ?: "Ошибка настроек")
            }
        }
        v.findViewById<Button>(R.id.btn_copy_gen).setOnClickListener {
            copySecret(activity, tvResult.text.toString())
        }
        if (onUse != null) {
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val t = tvResult.text.toString()
                if (t.isNotEmpty()) { onUse(t); dlg.dismiss() }
            }
        }
    }

    // ------------------------------------------------------------ слияние
    /**
     * Сводка перед слиянием. Позволяет разобраться со всем разом: раньше после
     * месяца врозь пользователь получал полсотни окон подряд.
     * Результат: "auto" | "manual" | null (отмена).
     */
    fun mergePreview(activity: Activity, plan: Merge.Plan, source: String,
                     onChoice: (String?) -> Unit) {
        val ambiguous = plan.conflicts.count { it.sameTimestamp }
        val auto = plan.conflicts.size - ambiguous
        val text = StringBuilder()
        text.append("$source\n\n")
        text.append("Добавится: ${plan.toAdd.size}\n")
        text.append("Расхождений: ${plan.conflicts.size}")
        if (ambiguous > 0) text.append("\nПравились одновременно: $ambiguous")

        val b = AlertDialog.Builder(activity)
            .setTitle("Слияние")
            .setMessage(text.toString())
            .setCancelable(true)
            .setOnCancelListener { onChoice(null) }
            .setNegativeButton("Отмена") { _, _ -> onChoice(null) }
        if (plan.conflicts.isEmpty()) {
            b.setPositiveButton("Слить") { _, _ -> onChoice("auto") }
        } else {
            b.setPositiveButton("Взять самое свежее") { _, _ -> onChoice("auto") }
            b.setNeutralButton("По одному") { _, _ -> onChoice("manual") }
        }
        b.show()
    }

    /**
     * Конфликт: обе версии целиком. onDecision(null, _) — пользователь отменил,
     * всё слияние откатывается без изменений.
     */
    fun conflict(activity: Activity, c: Merge.Conflict, index: Int, total: Int,
                 onDecision: (Merge.Decision?, Boolean) -> Unit) {

        fun card(caption: String, e: Entry, newer: Boolean): LinearLayout {
            val box = LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(32, 20, 32, 20)
            }
            fun tv(text: String, bold: Boolean = false, mono: Boolean = false,
                   gray: Boolean = false) {
                box.addView(TextView(activity).apply {
                    this.text = text
                    if (bold) setTypeface(null, Typeface.BOLD)
                    if (mono) typeface = Typeface.MONOSPACE
                    if (gray) alpha = 0.6f
                })
            }
            tv(caption + (if (newer) "   • новее" else ""), bold = true)
            if (e.deleted) {
                tv("ЗАПИСЬ УДАЛЕНА", bold = true)
                tv("удалена: ${Ts.display(e.modified)}", gray = true)
            } else {
                tv("Название: ${e.title}")
                tv("Логин: ${e.login}")
                tv("Пароль: ${e.password}", mono = true)
                if (e.url.isNotBlank()) tv("Адрес: ${e.url}")
                if (e.notes.isNotBlank()) tv("Заметки: ${e.notes.take(300)}")
                tv("изменено ${Ts.display(e.modified)}   ·   создано ${Ts.display(e.created)}",
                    gray = true)
            }
            return box
        }

        val root = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(card("НА ТЕЛЕФОНЕ", c.local, !c.incomingIsNewer && !c.sameTimestamp))
        root.addView(card("В ИМПОРТИРУЕМОМ ФАЙЛЕ", c.incoming, c.incomingIsNewer && !c.sameTimestamp))

        if (c.sameTimestamp) {
            root.addView(TextView(activity).apply {
                text = "Правились одновременно"
                setPadding(32, 8, 32, 8)
                setTypeface(null, Typeface.BOLD)
            })
        }

        val cbAll = CheckBox(activity).apply {
            text = "Применить ко всем оставшимся (${total - index + 1} шт.)"
            setPadding(32, 8, 32, 8)
            visibility = if (total > 1) android.view.View.VISIBLE else android.view.View.GONE
        }
        root.addView(cbAll)

        val scroll = ScrollView(activity).apply { addView(root) }
        val builder = AlertDialog.Builder(activity)
            .setTitle("Расхождение $index из $total")
            .setView(scroll)
            .setCancelable(true)
            .setOnCancelListener { onDecision(null, false) }
            .setPositiveButton("Оставить с телефона") { _, _ ->
                onDecision(Merge.Decision.LOCAL, cbAll.isChecked)
            }
            .setNegativeButton("Взять из файла") { _, _ ->
                onDecision(Merge.Decision.INCOMING, cbAll.isChecked)
            }
        if (!c.local.deleted && !c.incoming.deleted)
            builder.setNeutralButton("Оставить обе") { _, _ ->
                onDecision(Merge.Decision.BOTH, cbAll.isChecked)
            }
        builder.show()
    }

    // ------------------------------------------------------------ корзина
    /**
     * Удалённые записи всегда лежали в файле «надгробиями», но посмотреть их
     * было негде. Это самый частый случай «ой, я удалил не то».
     */
    fun trash(activity: Activity, onChanged: () -> Unit) {
        val items = VaultRepo.trashed().sortedByDescending { Ts.sortKey(it.modified) }
        if (items.isEmpty()) {
            AlertDialog.Builder(activity)
                .setTitle("Корзина")
                .setMessage("Корзина пуста.")
                .setPositiveButton("OK", null)
                .show()
            return
        }
        val labels = items.map { "${it.displayTitle}\nудалена ${Ts.display(it.modified)}" }
            .toTypedArray()

        AlertDialog.Builder(activity)
            .setTitle("Корзина (${items.size})")
            .setItems(labels) { _, which ->
                val e = items[which]
                AlertDialog.Builder(activity)
                    .setTitle(e.displayTitle)
                    .setMessage("Что сделать с записью?")
                    .setPositiveButton("Восстановить") { _, _ ->
                        VaultRepo.restore(e)
                        saveOrReport(activity, activity.filesDir)
                        onChanged()
                        toast(activity, "Запись восстановлена")
                    }
                    .setNegativeButton("Отмена", null)
                    .setNeutralButton("Стереть навсегда") { _, _ ->
                        AlertDialog.Builder(activity)
                            .setTitle("Стереть навсегда")
                            .setMessage("Отменить будет нельзя.")
                            .setPositiveButton("Стереть") { _, _ ->
                                VaultRepo.entries.remove(e)
                                saveOrReport(activity, activity.filesDir)
                                onChanged()
                            }
                            .setNegativeButton("Отмена", null)
                            .show()
                    }
                    .show()
            }
            .setPositiveButton("Восстановить всё") { _, _ ->
                items.forEach { VaultRepo.restore(it) }
                saveOrReport(activity, activity.filesDir)
                onChanged()
                toast(activity, "Восстановлено записей: ${items.size}")
            }
            .setNegativeButton("Закрыть", null)
            .show()
    }

    // ------------------------------------------------------------ история паролей
    fun history(activity: Activity, e: Entry, onRestore: (String) -> Unit) {
        if (e.history.isEmpty()) {
            AlertDialog.Builder(activity)
                .setTitle("История паролей")
                .setMessage("Пусто")
                .setPositiveButton("OK", null)
                .show()
            return
        }
        val labels = e.history.map { "${it.password}\nзаменён ${Ts.display(it.changed)}" }
            .toTypedArray()
        AlertDialog.Builder(activity)
            .setTitle("Прошлые пароли (${e.history.size})")
            .setItems(labels) { _, which ->
                val h = e.history[which]
                AlertDialog.Builder(activity)
                    .setTitle("Прошлый пароль")
                    .setMessage(h.password)
                    .setPositiveButton("Копировать") { _, _ ->
                        copySecret(activity, h.password)
                        toast(activity, "Скопировано")
                    }
                    .setNeutralButton("Сделать текущим") { _, _ -> onRestore(h.password) }
                    .setNegativeButton("Отмена", null)
                    .show()
            }
            .setNegativeButton("Закрыть", null)
            .show()
    }

    // ------------------------------------------------------------ резервные копии
    fun backups(activity: Activity, onRestore: (Backups.Snapshot) -> Unit) {
        val dir = activity.filesDir
        val snaps = Backups.list(dir)
        val header = "Снимков: ${snaps.size}  ·  ${humanSize(Backups.totalSize(dir))}"

        if (snaps.isEmpty()) {
            AlertDialog.Builder(activity)
                .setTitle("Резервные копии")
                .setMessage("Снимков нет")
                .setPositiveButton("Создать сейчас") { _, _ ->
                    val s = VaultRepo.snapshot(dir, null)
                    toast(activity, if (s != null) "Снимок создан" else "Не удалось создать снимок")
                }
                .setNegativeButton("Закрыть", null)
                .show()
            return
        }

        val labels = snaps.map { "${it.label()}\n${humanSize(it.size)}" }.toTypedArray()
        AlertDialog.Builder(activity)
            .setTitle("Резервные копии")
            .setMessage(header)
            .setItems(labels) { _, which ->
                val s = snaps[which]
                AlertDialog.Builder(activity)
                    .setTitle("Восстановление")
                    .setMessage("Снимок от ${s.label()}")
                    .setPositiveButton("Восстановить") { _, _ -> onRestore(s) }
                    .setNegativeButton("Отмена", null)
                    .show()
            }
            .setPositiveButton("Снимок сейчас") { _, _ ->
                val s = VaultRepo.snapshot(dir, null)
                toast(activity, if (s != null) "Снимок создан" else "Не удалось создать снимок")
            }
            .setNegativeButton("Закрыть", null)
            .show()
    }
}
