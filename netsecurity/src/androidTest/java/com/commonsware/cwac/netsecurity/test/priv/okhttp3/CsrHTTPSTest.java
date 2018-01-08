/***
 Copyright (c) 2016 CommonsWare, LLC
 Licensed under the Apache License, Version 2.0 (the "License"); you may not
 use this file except in compliance with the License. You may obtain a copy
 of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless required
 by applicable law or agreed to in writing, software distributed under the
 License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 OF ANY KIND, either express or implied. See the License for the specific
 language governing permissions and limitations under the License.
 */

package com.commonsware.cwac.netsecurity.test.priv.okhttp3;

import android.support.test.InstrumentationRegistry;

import com.commonsware.cwac.netsecurity.TrustManagerBuilder;
import com.commonsware.cwac.netsecurity.test.AbstractOkHttp3TestV2;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CsrHTTPSTest extends AbstractOkHttp3TestV2 {

    private SSLSocketFactory socketFactory;

    @Override
    protected String getUrl() {
        return ("https://env-53982.customer.cloud.microstrategy.com:3443/org/orgbasicinfo/2");
    }

    @Override
    protected TrustManagerBuilder getBuilder() {
        return new TrustManagerBuilder().withManifestConfig(InstrumentationRegistry.getContext());
    }


    public X509TrustManager construct() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
            throw new IllegalStateException("Unexpected default trust managers:"
                    + Arrays.toString(trustManagers));
        }

        return (X509TrustManager) trustManagers[0];

    }

    @Override
    protected SSLSocketFactory getSSLSocketFactory() throws Exception {

//        if (socketFactory != null) {
//            return socketFactory;
//        }
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers(), new X509TrustManager[]{construct()}, null);
            socketFactory = sslContext.getSocketFactory();
            return socketFactory;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }

    protected KeyManager[] keyManagers() throws Exception {

        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            KeyStore keyStore = provideKeyStore();
            kmf.init(keyStore, "13".toCharArray());
            return kmf.getKeyManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }


    public KeyStore provideKeyStore() {

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(InstrumentationRegistry.getContext().getAssets().open("cert.p12"), "123".toCharArray());
            return keyStore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return null;

    }

    protected String getExpectedResponse() {
        return ("{\"org_requires_login\":false,\"org_name\":\"Usher_Benchmark_2\"}");
    }


}
