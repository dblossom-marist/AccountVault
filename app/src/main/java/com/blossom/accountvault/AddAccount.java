package com.blossom.accountvault;

import android.content.ContentValues;
import android.database.sqlite.SQLiteDatabase;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

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

        byte iv[] = null;
        byte encryption[] = null;

        try {
            final KeyGenerator keyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenParameterSpec = new KeyGenParameterSpec.Builder(accName.getText().toString(),
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build();
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator.init(keyGenParameterSpec);
            }
            final SecretKey secretKey = keyGenerator.generateKey();

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            iv = cipher.getIV();

            encryption = cipher.doFinal(hexSecureKey.getBytes("UTF-8"));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
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
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

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
        // No longer storing key in DB but in KeyStore
        // convert byte array to string since we are storing text
        values.put("ivKey", iv);
        values.put("encrypt", encryption);

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
