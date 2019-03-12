/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aletheiaware.alias.utils;

import com.aletheiaware.alias.AliasProto.Alias;
import com.aletheiaware.bc.BC.Channel;
import com.aletheiaware.bc.BC.Channel.EntryCallback;
import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.BlockEntry;
import com.aletheiaware.bc.BCProto.PublicKeyFormat;
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.BCProto.SignatureAlgorithm;
import com.aletheiaware.bc.utils.BCUtils;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HttpsURLConnection;

public final class AliasUtils {

    public static final String ALIAS_CHANNEL = "Alias";

    private AliasUtils() {}

    /**
     * Registers the alias and public key (private key used for signature).
     */
    public static void registerAlias(String alias, KeyPair keys) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        byte[] publicKeyBytes = keys.getPublic().getEncoded();
        String publicKey = new String(BCUtils.encodeBase64URL(publicKeyBytes));
        Alias.Builder ab = Alias.newBuilder()
            .setAlias(alias)
            .setPublicKey(ByteString.copyFrom(publicKeyBytes));
        String publicKeyFormat = keys.getPublic().getFormat().replaceAll("\\.", "");// Remove dot from X.509
        switch(publicKeyFormat) {
            case "X509":
                ab.setPublicFormat(PublicKeyFormat.X509);
                break;
            default:
                System.out.println("Unsupported Public Key Format: " + publicKeyFormat);
        }
        byte[] signature = BCUtils.sign(keys.getPrivate(), ab.build().toByteArray());
        String params = "alias=" + URLEncoder.encode(alias, "utf-8")
                + "&publicKey=" + URLEncoder.encode(publicKey, "utf-8")
                + "&publicKeyFormat=" + URLEncoder.encode(publicKeyFormat, "utf-8")
                + "&signature=" + URLEncoder.encode(new String(BCUtils.encodeBase64URL(signature)), "utf-8")
                + "&signatureAlgorithm=" + URLEncoder.encode(SignatureAlgorithm.SHA512WITHRSA.toString(), "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(BCUtils.BC_WEBSITE + "/alias");
        System.out.println("URL:" + url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Content-Length", Integer.toString(data.length));
        conn.setUseCaches(false);
        try (OutputStream o = conn.getOutputStream()) {
            o.write(data);
            o.flush();
        }

        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        Scanner in = new Scanner(conn.getInputStream());
        while (in.hasNextLine()) {
            System.out.println(in.nextLine());
        }
    }

    /**
     * Returns true iff the given alias is unique (has not already been registered)
     */
    public static boolean isUnique(InetAddress address, String alias) throws IOException {
        Reference head = BCUtils.getHead(address, Reference.newBuilder()
                .setChannelName(ALIAS_CHANNEL)
                .build());
        if (head != null) {
            ByteString bh = head.getBlockHash();
            while (bh != null && !bh.isEmpty()) {
                Block b = BCUtils.getBlock(address, Reference.newBuilder()
                        .setBlockHash(bh)
                        .setChannelName(ALIAS_CHANNEL)
                        .build());
                if (b == null) {
                    break;
                }
                for (BlockEntry e : b.getEntryList()) {
                    Record r = e.getRecord();
                    ByteString p = r.getPayload();
                    Alias.Builder ab = Alias.newBuilder();
                    try {
                        ab.mergeFrom(p);
                    } catch (InvalidProtocolBufferException ex) {
                        ex.printStackTrace();
                    }
                    Alias a = ab.build();
                    if (a.getAlias().equals(alias)) {
                        return false;
                    }
                }
                bh = b.getPrevious();
            }
        }
        return true;
    }
}