package com.blossom.accountvault;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class AccountView extends AppCompatActivity {

    TextView accountName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_account_view);

        accountName = findViewById(R.id.txtAccountName);
        accountName.setText(getIntent().getStringExtra("accountName"));
        accountName.setTextSize(40);
    }
}
