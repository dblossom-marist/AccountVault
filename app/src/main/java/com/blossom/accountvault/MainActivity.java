package com.blossom.accountvault;

import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;


import java.util.ArrayList;

public class MainActivity extends AppCompatActivity {

    /**
     * Global Variables section
     */
    // The list of account names for the List View for user
    ArrayList<String> accountNames = new ArrayList<>();
    // The database connection.
    SQLiteDatabase myDatabase;

    //TODO: Try centralize DB stuff, not working ATM - bug report #
    //Database myDatabase;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //myDatabase = new Database();

        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE, null);

        /**
         * In case you want to drop the table on next run ...
         */
        //myDatabase.execSQL("DROP TABLE accounts");

        myDatabase.execSQL("CREATE TABLE IF NOT EXISTS accounts" +
                "(account_name text, user_name text, email text, " +
                "password text, account_number text, security text," +
                "hexkey text);");

        accountNames = generateExistingAccountListing(myDatabase);

        ArrayAdapter adapter = new ArrayAdapter<>(this,
                R.layout.activity_listview, accountNames);

        ListView listView = findViewById(R.id.mobile_list);
        listView.setAdapter(adapter);

        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Intent intent = new Intent(view.getContext(), AccountView.class);
                intent.putExtra("accountName",accountNames.get(position));
                startActivity(intent);
                //startActivityForResult(intent,0);
            }
        });
    }

    public void addAccountButton(View view){
        Intent intent = new Intent(this, AddAccount.class);
        startActivity(intent);
    }

    private ArrayList<String> generateExistingAccountListing(SQLiteDatabase database){

        ArrayList<String> returnList =  new ArrayList<>();

        //Cursor resultSet = database.getAllAccounts();
        Cursor resultSet = database.rawQuery("Select account_name, hexkey from accounts",
                null);
        resultSet.moveToFirst();

        while(!resultSet.isAfterLast()){

            String accountName = resultSet.getString(
                                 resultSet.getColumnIndex("account_name"));

            //String decryptKey = resultSet.getString(
            //                    resultSet.getColumnIndex("hexkey"));
            //AEScipher aesCipher = new AEScipher();
            //String decryptedName = aesCipher.decrypt(accountName, decryptKey);
            returnList.add(accountName);
            resultSet.moveToNext();

        }
        return returnList;
    }

    @Override
    protected void onRestart(){
        super.onRestart();

        accountNames = generateExistingAccountListing(myDatabase);
        ArrayAdapter adapter = new ArrayAdapter<>(this,
                R.layout.activity_listview, accountNames);

        ListView listView = findViewById(R.id.mobile_list);
        listView.setAdapter(adapter);
    }


}
