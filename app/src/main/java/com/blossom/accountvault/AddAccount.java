package com.blossom.accountvault;

/**
 * This class is called when a user wants to add an account to their application
 *
 * @author D. Blossom
 * @version 5/5/2019
 */

/**
 * Lots of imports
 */
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

/**
 * Class declaration
 */
public class AddAccount extends AppCompatActivity {

    // My database to write to.
    SQLiteDatabase myDatabase;

    /**
     * The view creation
     * @param savedInstanceState
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_add_account);
    }

    /**
     * The submit button, that will write information to database
     * @param view the view
     */
    public void submitButton(View view){

        myDatabase = openOrCreateDatabase("account_vault",
                MODE_PRIVATE,null);

        // All the text fields in said view.
        TextView accName = findViewById(R.id.txtAccountName);
        TextView user = findViewById(R.id.txtUserName);
        TextView email = findViewById(R.id.txtEmail);
        TextView pwd = findViewById(R.id.txtPassword);
        TextView accNum = findViewById(R.id.txtAccountNumber);
        TextView security = findViewById(R.id.txtSecurity);

        // The values we will write into DB
        ContentValues values = new ContentValues();

        // Our AES class & generate a random key
        AEScipher aesCipher = new AEScipher();
        String hexSecureKey = aesCipher.randomKey();

        // Our initialization vector & encrypted key
        // We need to keep our AES key safe, so we will
        // too encrypt that using Android KeyStore!
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

        // Here we encrypt everything
        String encryptedUser = aesCipher.encrypt(user.getText().toString(), hexSecureKey);
        String encryptedEmail = aesCipher.encrypt(email.getText().toString(), hexSecureKey);
        String encryptedPwd = aesCipher.encrypt(pwd.getText().toString(), hexSecureKey);
        String encryptedAccNum = aesCipher.encrypt(accNum.getText().toString(), hexSecureKey);
        String encryptedSecurity = aesCipher.encrypt(security.getText().toString(), hexSecureKey);

        // Here we store those things in the DB
        values.put("account_name", accName.getText().toString());
        values.put("user_name", encryptedUser);
        values.put("email", encryptedEmail);
        values.put("password", encryptedPwd);
        values.put("account_number", encryptedAccNum);
        values.put("security", encryptedSecurity);
        // No longer storing key in DB but in KeyStore
        // Here is the encrypted key and IV for said key
        values.put("ivKey", iv);
        values.put("encrypt", encryption);

        // insert, it's official
        myDatabase.insert("accounts",null,values);

        // That's a wrap!
        myDatabase.close();

        // Clear fields.
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
