package com.blossom.accountvault;

import android.content.ContentValues;
import android.database.sqlite.SQLiteDatabase;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class AddAccount extends AppCompatActivity {

    SQLiteDatabase myDatabase;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_add_account);
    }

    public void submitButton(View view){

        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE,null);

        TextView accName = findViewById(R.id.txtAccountName);
        TextView user = findViewById(R.id.txtUserName);
        TextView email = findViewById(R.id.txtEmail);
        TextView pwd = findViewById(R.id.txtPassword);
        TextView accNum = findViewById(R.id.txtAccountNumber);
        TextView security = findViewById(R.id.txtSecurity);

        ContentValues values = new ContentValues();

        //TODO: Here is where we can encrypt the strings, create a method

        AEScipher aesCipher = new AEScipher();
        String hexSecureKey = aesCipher.randomKey();
        //String encryptedAccName = aesCipher.encrypt(accName.getText().toString(), hexSecureKey);
        String encryptedUser = aesCipher.encrypt(user.getText().toString(), hexSecureKey);
        String encryptedEmail = aesCipher.encrypt(email.getText().toString(), hexSecureKey);
        String encryptedPwd = aesCipher.encrypt(pwd.getText().toString(), hexSecureKey);
        String encryptedAccNum = aesCipher.encrypt(accNum.getText().toString(), hexSecureKey);
        String encryptedSecurity = aesCipher.encrypt(security.getText().toString(), hexSecureKey);

        //values.put("account_name",encryptedAccName);
        values.put("account_name", accName.getText().toString());
        values.put("user_name", encryptedUser);
        values.put("email", encryptedEmail);
        values.put("password", encryptedPwd);
        values.put("account_number", encryptedAccNum);
        values.put("security", encryptedSecurity);
        values.put("hexkey", hexSecureKey);

        myDatabase.insert("accounts",null,values);

        myDatabase.close();

        accName.setText("");
        user.setText("");
        email.setText("");
        pwd.setText("");
        accNum.setText("");
        security.setText("");

        //TODO: This doesn't work, I'd like some kind of message to user
        //      so they know the details entered were saved.
        Snackbar.make(view, "Details Saved" ,500).show();

        finish();
    }
}
