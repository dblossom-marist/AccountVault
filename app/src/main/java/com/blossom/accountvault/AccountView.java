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

        //myDatabase.execSQL("CREATE TABLE IF NOT EXISTS accounts" +
        //        "(account_name text, user_name text, email text, " +
        //        "password text, account_number text, security text);");

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

        user.setText(cursor.getString(1));
        email.setText(cursor.getString(2));
        pwd.setText(cursor.getString(3));
        accNum.setText(cursor.getString(4));
        security.setText(cursor.getString(5));

    }
}
