package com.example.passvault

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.text.InputType
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class EntryActivity : AppCompatActivity() {

    private var entryId: String = ""
    private lateinit var etTitle: EditText
    private lateinit var etLogin: EditText
    private lateinit var etPass: EditText
    private lateinit var etUrl: EditText
    private lateinit var etNotes: EditText
    private lateinit var tvMeta: TextView

    /**
     * Пароль на момент открытия записи. Прежний пароль уходит в историю при
     * уходе с экрана, а не на каждое нажатие клавиши — иначе история забилась
     * бы огрызками набираемого текста.
     */
    private var baselinePassword: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_entry)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        entryId = intent.getStringExtra("id") ?: ""

        etTitle = findViewById(R.id.et_title)
        etLogin = findViewById(R.id.et_login)
        etPass = findViewById(R.id.et_pass)
        etUrl = findViewById(R.id.et_url)
        etNotes = findViewById(R.id.et_notes)
        tvMeta = findViewById(R.id.tv_meta)

        findViewById<CheckBox>(R.id.cb_show).setOnCheckedChangeListener { _, show ->
            etPass.inputType = InputType.TYPE_CLASS_TEXT or
                    (if (show) InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                     else InputType.TYPE_TEXT_VARIATION_PASSWORD)
            etPass.setSelection(etPass.text.length)
        }
        findViewById<Button>(R.id.btn_copy).setOnClickListener { copyPassword() }
        findViewById<Button>(R.id.btn_gen).setOnClickListener {
            Dialogs.generator(this) { pwd ->
                etPass.setText(pwd)
                findViewById<CheckBox>(R.id.cb_show).isChecked = true
            }
        }
        findViewById<Button>(R.id.btn_history).setOnClickListener {
            val e = VaultRepo.entryById(entryId) ?: return@setOnClickListener
            persist()                       // чтобы история была актуальной
            Dialogs.history(this, e) { old ->
                etPass.setText(old)
                findViewById<CheckBox>(R.id.cb_show).isChecked = true
                Dialogs.toast(this, "Пароль возвращён из истории")
            }
        }
        findViewById<Button>(R.id.btn_delete).setOnClickListener { confirmDelete() }
        load()
    }

    private fun load() {
        val e = VaultRepo.entryById(entryId)
        if (e == null) { finish(); return }
        etTitle.setText(e.title)
        etLogin.setText(e.login)
        etPass.setText(e.password)
        etUrl.setText(e.url)
        etNotes.setText(e.notes)
        baselinePassword = e.password
        refreshMeta(e)
    }

    private fun refreshMeta(e: Entry) {
        val hist = if (e.history.isEmpty()) "" else "   ·   прошлых паролей: ${e.history.size}"
        tvMeta.text = "создано ${Ts.display(e.created)}   ·   " +
                "изменено ${Ts.display(e.modified)}$hist"
    }

    /**
     * Автосохранение: как в заметках — при уходе с экрана всё пишется в файл.
     *
     * Записываем ТОЛЬКО если что-то действительно изменилось. Раньше файл
     * перезаписывался при каждом уходе с экрана, даже когда человек просто
     * посмотрел запись и вышел: полная перешифровка хранилища, ротация .prev
     * и лишний износ флеша на ровном месте.
     */
    private fun persist() {
        val e = VaultRepo.entryById(entryId) ?: return
        val nt = etTitle.text.toString()
        val nl = etLogin.text.toString()
        val np = etPass.text.toString()
        val nu = etUrl.text.toString()
        val nn = etNotes.text.toString()
        val changed = nt != e.title || nl != e.login || np != e.password ||
                nu != e.url || nn != e.notes
        if (!changed) return

        if (np != baselinePassword) {
            e.pushHistory(baselinePassword)
            baselinePassword = np
        }
        e.title = nt; e.login = nl; e.password = np; e.url = nu; e.notes = nn
        e.modified = Ts.now()
        Dialogs.saveOrReport(this, filesDir)
    }

    override fun onPause() {
        if (VaultRepo.unlocked) persist()
        super.onPause()
    }

    override fun onResume() {
        super.onResume()
        if (VaultRepo.expired()) VaultRepo.lock()
        if (!VaultRepo.unlocked) { finish(); return }
        VaultRepo.touch()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        VaultRepo.touch()
    }

    private fun copyPassword() = Dialogs.copySecret(this, etPass.text.toString())

    private fun confirmDelete() {
        val e = VaultRepo.entryById(entryId) ?: return
        AlertDialog.Builder(this)
            .setTitle("Удалить запись")
            .setMessage("Удалить «${e.title.ifBlank { "(без названия)" }}»?")
            .setPositiveButton("Удалить") { _, _ ->
                VaultRepo.softDelete(e)
                Dialogs.saveOrReport(this, filesDir)
                finish()
            }
            .setNegativeButton("Отмена", null)
            .show()
    }
}
