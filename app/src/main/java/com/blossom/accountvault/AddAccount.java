package com.blossom.accountvault;

import android.content.ContentValues;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.ListView;
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

        values.put("account_name",accName.getText().toString());
        values.put("user_name", user.getText().toString());
        values.put("email", email.getText().toString());
        values.put("password", pwd.getText().toString());
        values.put("account_number", accNum.getText().toString());
        values.put("security", security.getText().toString());

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
