package info.firozansari.keystoresample;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;


public class MainActivity extends AppCompatActivity{

    /*The Keystore is not used directly for storing application secrets such as password, however,
    it provides a secure container, which can be used by apps to store their private keys, in a way
    that’s pretty difficult for malicious (unauthorised) users and apps to retrieve. As its name
    suggests, an app can store multiple keys in the Keystore, but an app can only view, and query,
    its own keys. Ideally, with the keystore, an app would generate/or receive a private/public key
    pair, which would be stored in the keystore. The public key can then be used to encrypt
    application secrets, before being stored in the app specific folders, with the private key
    used to decrypt the same information when needed. Although the Android Keystore provider was
    introduced in API level 18 (Android 4.3), the Keystore itself has been available since API 1,
    restricted to use by VPN and WiFi systems. The Keystore itself is encrypted using the user’s
    own lockscreen pin/password, hence, when the device screen is locked the Keystore is unavailable.
    Keep this in mind if you have a background service that could need to access your application secrets.*/

    private static final String TAG = "KeystoreSample";
    private static final String AndroidKeyStore = "AndroidKeyStore";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String RSA_MODE =  "RSA/ECB/PKCS1Padding";
    private static final String SHARED_PREFENCE_NAME =  "info.firozansari.keystoresample";
    private static final String ENCRYPTED_KEY =  "encrypted_key";
    private static String KEY_ALIAS = "";

    Button generateBtn;
    EditText aliasText;
    EditText startText, decryptedText, encryptedText;
    List<String> keyAliases;
    ListView listView;
    KeyRecyclerAdapter listAdapter;

    KeyStore keyStore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            keyStore = KeyStore.getInstance(AndroidKeyStore);
            keyStore.load(null);
        }
        catch(Exception e) {

        }
        refreshKeys();

        setContentView(R.layout.activity_main);

        View listHeader = View.inflate(this, R.layout.activity_main_header, null);
        aliasText = (EditText) listHeader.findViewById(R.id.aliasText);
        startText = (EditText) listHeader.findViewById(R.id.startText);
        decryptedText = (EditText) listHeader.findViewById(R.id.decryptedText);
        encryptedText = (EditText) listHeader.findViewById(R.id.encryptedText);

        listView = (ListView) findViewById(R.id.listView);
        listView.addHeaderView(listHeader);
        listAdapter = new KeyRecyclerAdapter(this, R.id.keyAlias);
        listView.setAdapter(listAdapter);

        generateBtn = (Button) listHeader.findViewById(R.id.generateKeyPair);
        generateBtn.setOnClickListener( new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                KEY_ALIAS = aliasText.getText().toString();
                if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){
                    createNewKeysNewAPI(v, KEY_ALIAS);
                } else{
                    try {
                        createNewKeysOldAPI(v, KEY_ALIAS);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                refreshKeys();
            }
        });
    }

    private void refreshKeys() {
        keyAliases = new ArrayList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement());
            }
        }
        catch(Exception e) {}

        if(listAdapter != null)
            listAdapter.notifyDataSetChanged();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void createNewKeysNewAPI(View view, String alias) {
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(alias)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore);
                keyGenerator.init(
                        new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setRandomizedEncryptionRequired(false)
                                .build());
                keyGenerator.generateKey();
            }
        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    public void createNewKeysOldAPI(View view, String alias) throws Exception {
        /* Generate a pair of RSA keys;
         * Generate a random AES key;
         * Encrypt the AES key using the RSA public key;
         * Store the encrypted AES key in Preferences. */

        // Generate the RSA key pairs
        if (!keyStore.containsAlias(alias)) {
            // Generate a key pair for encryption
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 30);
            KeyPairGeneratorSpec spec = new      KeyPairGeneratorSpec.Builder(MainActivity.this)
                    .setAlias(alias)
                    .setSubject(new X500Principal("CN=" + alias))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, AndroidKeyStore);
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }

        SharedPreferences pref = getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE);
        String enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);
        if (enryptedKeyB64 == null) {
            byte[] key = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(key);
            byte[] encryptedKey = rsaEncrypt(key);
            enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
            SharedPreferences.Editor edit = pref.edit();
            edit.putString(ENCRYPTED_KEY, enryptedKeyB64);
            edit.commit();
        }

    }

    private byte[] rsaEncrypt(byte[] secret) throws Exception{
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        // Encrypt the text
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secret);
        cipherOutputStream.close();

        byte[] vals = outputStream.toByteArray();
        return vals;
    }

    private  byte[]  rsaDecrypt(byte[] encrypted) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);
        Cipher output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(encrypted), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte)nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }
        return bytes;
    }

    private Key getSecretKey(Context context) throws Exception{
        SharedPreferences pref = context.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE);
        String enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);
        // need to check null, omitted here
        byte[] encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT);
        byte[] key = rsaDecrypt(encryptedKey);
        return new SecretKeySpec(key, "AES");
    }

    public String encrypt(Context context, byte[] input) throws Exception {
        Cipher c = Cipher.getInstance(AES_MODE, "BC");
        c.init(Cipher.ENCRYPT_MODE, getSecretKey(context));
        byte[] encodedBytes = c.doFinal(input);
        String encryptedBase64Encoded =  Base64.encodeToString(encodedBytes, Base64.DEFAULT);
        return encryptedBase64Encoded;
    }

    public void deleteKey(final String alias) {
        AlertDialog alertDialog =new AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"" + alias + "\" from the keystore?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        try {
                            keyStore.deleteEntry(alias);
                            refreshKeys();
                        } catch (KeyStoreException e) {
                            Toast.makeText(MainActivity.this,
                                    "Exception " + e.getMessage() + " occured",
                                    Toast.LENGTH_LONG).show();
                            Log.e(TAG, Log.getStackTraceString(e));
                        }
                        dialog.dismiss();
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .create();
        alertDialog.show();
    }

    public void encryptString(String alias) {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            String initialText = startText.getText().toString();
            if(initialText.isEmpty()) {
                Toast.makeText(this, "Enter text in the 'Initial Text' widget", Toast.LENGTH_LONG).show();
                return;
            }

            Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);
            cipherOutputStream.write(initialText.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte [] vals = outputStream.toByteArray();
            encryptedText.setText(Base64.encodeToString(vals, Base64.DEFAULT));
        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    public void decryptString(String alias) {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            String cipherText = encryptedText.getText().toString();
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            String finalText = new String(bytes, 0, bytes.length, "UTF-8");
            decryptedText.setText(finalText);

        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }


    public class KeyRecyclerAdapter extends ArrayAdapter<String> {

        public KeyRecyclerAdapter(Context context, int textView) {
            super(context, textView);
        }

        @Override
        public int getCount() {
            return keyAliases.size();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View itemView = LayoutInflater.from(parent.getContext()).
                    inflate(R.layout.list_item, parent, false);

            final TextView keyAlias = (TextView) itemView.findViewById(R.id.keyAlias);
            keyAlias.setText(keyAliases.get(position));
            Button encryptButton = (Button) itemView.findViewById(R.id.encryptButton);
            encryptButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    encryptString(keyAlias.getText().toString());
                }
            });
            Button decryptButton = (Button) itemView.findViewById(R.id.decryptButton);
            decryptButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    decryptString(keyAlias.getText().toString());
                }
            });
            final Button deleteButton = (Button) itemView.findViewById(R.id.deleteButton);
            deleteButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    deleteKey(keyAlias.getText().toString());
                }
            });

            return itemView;
        }

        @Override
        public String getItem(int position) {
            return keyAliases.get(position);
        }

    }
}
