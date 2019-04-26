package com.blossom.accountvault;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class AccountView extends AppCompatActivity {

    TextView accountName;
    SQLiteDatabase myDatabase;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_account_view);

        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE, null);

        accountName = findViewById(R.id.txtAccountName);
        accountName.setText(getIntent().getStringExtra("accountName"));
        accountName.setTextSize(40);

        displayAccountInformation(getIntent().getStringExtra("accountName"));
    }

    private void displayAccountInformation(String aName){


        TextView user = findViewById(R.id.txtUserName);
        TextView email = findViewById(R.id.txtEmail);
        TextView pwd = findViewById(R.id.txtPassword);
        TextView accNum = findViewById(R.id.txtAccNum);
        TextView security = findViewById(R.id.txtSecurity);

        //Database database = new Database();

        //Cursor cursor = database.getAccountInformation(aName);
        Cursor cursor = myDatabase.rawQuery("SELECT * from accounts WHERE account_name=?",
                new String[] {aName});

        cursor.moveToFirst();

        String key = cursor.getString(6);

        AEScipher aesCipher = new AEScipher();

        user.setText(aesCipher.decrypt(cursor.getString(1),key));
        email.setText(aesCipher.decrypt(cursor.getString(2),key));
        pwd.setText(aesCipher.decrypt(cursor.getString(3),key));
        accNum.setText(aesCipher.decrypt(cursor.getString(4),key));
        security.setText(aesCipher.decrypt(cursor.getString(5),key));

    }
}
