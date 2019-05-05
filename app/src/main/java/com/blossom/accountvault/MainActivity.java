package com.blossom.accountvault;
/**
 * This class is the main class for the AccountValut program
 *
 * @author D. Blossom
 * @version Beta, extremely beta, please do not use in real life!
 */


/**
 * All my imports ...
 */

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

/**
 * The MainActivity class, which is the "front page" of the application
 */
public class MainActivity extends AppCompatActivity {

    /**
     * Global Variables section
     */
    // The list of account names for the List View for user
    ArrayList<String> accountNames = new ArrayList<>();
    // The database connection.
    SQLiteDatabase myDatabase;

    //TODO: Try centralize DB stuff, not working ATM - bug report #1
    //Database myDatabase;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //myDatabase = new Database();

        // Create DB
        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE, null);

        /**
         * In case you want to drop the table on next run ...
         * Useful for debugging to wipe DB or add tables etc
         */
        //myDatabase.execSQL("DROP TABLE accounts");

        // Create table if needed
        myDatabase.execSQL("CREATE TABLE IF NOT EXISTS accounts" +
                "(account_name text, user_name text, email text, " +
                "password text, account_number text, security text," +
                "ivKey blob, encrypt blob);");

        // Get a listing of all accounts
        accountNames = generateExistingAccountListing(myDatabase);

        // Set adapter and all that fun stuff - Android boilerplate
        ArrayAdapter adapter = new ArrayAdapter<>(this,
                R.layout.activity_listview, accountNames);

        ListView listView = findViewById(R.id.mobile_list);
        listView.setAdapter(adapter);

        // Set the listview to listen if someone clicks and wants to see the details
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Intent intent = new Intent(view.getContext(), AccountView.class);
                intent.putExtra("accountName",accountNames.get(position));
                startActivity(intent);
            }
        });
    }

    /**
     * Button that allows a user to add an account to the application
     * @param view the view to enter details
     */
    public void addAccountButton(View view){
        Intent intent = new Intent(this, AddAccount.class);
        startActivity(intent);
    }

    /**
     * A private helper method that gets the account name out of the database
     * @param database the database to retrieve the data from
     * @return a list of account names
     */
    private ArrayList<String> generateExistingAccountListing(SQLiteDatabase database){

        ArrayList<String> returnList =  new ArrayList<>();

        // Do the query
        Cursor resultSet = database.rawQuery("Select account_name from accounts",
                null);
        // Go to first
        resultSet.moveToFirst();

        // loopy until all accounts found
        while(!resultSet.isAfterLast()){

            String accountName = resultSet.getString(
                                 resultSet.getColumnIndex("account_name"));
            returnList.add(accountName);
            resultSet.moveToNext();

        }
        // ... AND return.
        return returnList;
    }

    /**
     * Stuff to do when we return (update account list mainly)
     */
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
