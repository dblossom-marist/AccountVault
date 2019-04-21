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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE,null);

        myDatabase.execSQL("CREATE TABLE IF NOT EXISTS accounts" +
                "(account_name text, user_name text, email text, " +
                "password text, account_number text, security text);");

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

    private ArrayList<String> generateExistingAccountListing(SQLiteDatabase db){

        ArrayList<String> returnList =  new ArrayList<>();

        Cursor resultSet = db.rawQuery("Select account_name from accounts",
                null);
        resultSet.moveToFirst();

        while(!resultSet.isAfterLast()){

            String s = resultSet.getString(0);
            returnList.add(s);
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
