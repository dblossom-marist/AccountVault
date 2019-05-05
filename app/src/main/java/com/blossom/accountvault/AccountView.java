package com.blossom.accountvault;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Build;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

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

        // this is just N/A now, we are keeping key in keystore
        //String key = cursor.getString(6);

        // However, we are storing the IV for the keystore there ... ?
        // Am I just moving around the vulnerability?
        byte[] ivKey = cursor.getBlob(6);
        byte[] ksEncrypt = cursor.getBlob(7);

        String key = getKeyFromStore(aName, ivKey, ksEncrypt);

        AEScipher aesCipher = new AEScipher();

        user.setText(aesCipher.decrypt(cursor.getString(1),key));
        email.setText(aesCipher.decrypt(cursor.getString(2),key));
        pwd.setText(aesCipher.decrypt(cursor.getString(3),key));
        accNum.setText(aesCipher.decrypt(cursor.getString(4),key));
        security.setText(aesCipher.decrypt(cursor.getString(5),key));
    }

    private String getKeyFromStore(String aName, byte[] ivKey, byte[] ksEncrypt) {

        byte[] decodedData = null;

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                    .getEntry(aName, null);

            final SecretKey secretKey = secretKeyEntry.getSecretKey();

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                spec = new GCMParameterSpec(128, ivKey);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            }
            decodedData = cipher.doFinal(ksEncrypt);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return new String(decodedData);
    }
}
