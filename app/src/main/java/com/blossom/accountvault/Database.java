package com.blossom.accountvault;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.support.v7.app.AppCompatActivity;

public class Database extends AppCompatActivity {

    SQLiteDatabase myDatabase;

    public Database(){
        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE, null);
        createAccountsTable();
    }

    protected Cursor getAllAccounts(){
        return myDatabase.rawQuery("Select account_name from accounts",
                null);
    }

    protected Cursor getAccountInformation(String accountName){
        return myDatabase.rawQuery("SELECT * from accounts WHERE account_name=?",
                new String[] {accountName});
    }

    private void createAccountsTable(){
        myDatabase.execSQL("CREATE TABLE IF NOT EXISTS accounts" +
                "(account_name text, user_name text, email text, " +
                "password text, account_number text, security text);");
    }





}
