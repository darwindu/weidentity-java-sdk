/*
 *       Copyright© (2018) WeBank Co., Ltd.
 *
 *       This file is part of weidentity-java-sdk.
 *
 *       weidentity-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weidentity-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weidentity-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.full.cpt;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Future;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.google.common.base.Splitter;
import mockit.Mock;
import mockit.MockUp;
import org.bcos.web3j.abi.FunctionEncoder;
import org.bcos.web3j.abi.datatypes.Address;
import org.bcos.web3j.abi.datatypes.Function;
import org.bcos.web3j.abi.datatypes.StaticArray;
import org.bcos.web3j.abi.datatypes.Type;
import org.bcos.web3j.abi.datatypes.generated.Bytes32;
import org.bcos.web3j.abi.datatypes.generated.Int256;
import org.bcos.web3j.abi.datatypes.generated.Uint8;
import org.bcos.web3j.crypto.Credentials;
import org.bcos.web3j.crypto.ECKeyPair;
import org.bcos.web3j.crypto.Sign.SignatureData;
import org.bcos.web3j.crypto.TransactionEncoder;
import org.bcos.web3j.protocol.core.methods.request.RawTransaction;
import org.bcos.web3j.protocol.core.methods.response.TransactionReceipt;
import org.bcos.web3j.tx.TransactionConstant;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.BeanUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.JsonSchemaConstant;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.CptController;
import com.webank.weid.contract.CptController.RegisterCptRetLogEventResponse;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CptStringArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.RsvSignature;
import com.webank.weid.util.DataTypetUtils;
import com.webank.weid.util.JsonUtil;
import com.webank.weid.util.SignatureUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * registerCpt method for testing CptService.
 * 
 * @author v_wbgyang
 *
 */
public class TestRegisterCpt extends TestBaseServcie {
    
    private static final Logger logger = LoggerFactory.getLogger(TestRegisterCpt.class);

    private static CreateWeIdDataResult createWeId = null;

    @Override
    public void testInit() {

        super.testInit();
        if (null == createWeId) {
            createWeId = super.createWeId();
            super.registerAuthorityIssuer(createWeId);
        }
    }

    /** 
     * case： cpt register success.
     */
    @Test
    public void testRegisterCptCase1() {

        CptMapArgs registerCptArgs = TestBaseUtil.buildCptArgs(createWeId);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(registerCptArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /** 
     * case： registerCptArgs is null.
     */
    @Test
    public void testRegisterCptCase2() {

        CptMapArgs cptMapArgs = null;
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： cptJsonSchema is null.
     */
    @Test
    public void testRegisterCptCase3() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.setCptJsonSchema(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_NULL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： Mock for ErrorCode.UNKNOW_ERROR.
     */
    @Test
    public void testRegisterCptCase4() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        MockUp<CptController> mockTest = new MockUp<CptController>() {
            @Mock
            public Future<TransactionReceipt> registerCpt(
                Address publisher,
                StaticArray<Int256> intArray,
                StaticArray<Bytes32> bytes32Array,
                StaticArray<Bytes32> jsonSchemaArray,
                Uint8 v,
                Bytes32 r,
                Bytes32 s) {
                return null;
            }
        };

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        mockTest.tearDown();

        Assert.assertEquals(ErrorCode.UNKNOW_ERROR.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptJsonSchema too long.
     */
    @Test
    public void testRegisterCptCase5() throws JsonProcessingException, IOException {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        StringBuffer value = new StringBuffer("");
        for (int i = 0; i < 5000; i++) {
            value.append("x");
        }

        HashMap<String, Object> cptJsonSchema = TestBaseUtil.buildCptJsonSchema();
        cptJsonSchema.put(JsonSchemaConstant.TITLE_KEY, value.toString());
        cptMapArgs.setCptJsonSchema(cptJsonSchema);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.CPT_JSON_SCHEMA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptPublisher is blank.
     */
    @Test
    public void testRegisterCptCase6() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptPublisher is invalid.
     */
    @Test
    public void testRegisterCptCase7() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId("di:weid:0xaaaaaaaaaaaaaaaa");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptPublisher is not exists and the private key does not match.
     */
    @Test
    public void testRegisterCptCase8() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId("did:weid:0xaaaaaaaaaaaaaaaa");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cpt register again.
     */
    @Test
    public void testRegisterCptCase9() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /** 
     * case： cptPublisherPrivateKey is null.
     */
    @Test
    public void testRegisterCptCase10() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeIdPrivateKey(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： privateKey is null.
     */
    @Test
    public void testRegisterCptCase11() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： privateKey is invalid.
     */
    @Test
    public void testRegisterCptCase12() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey("1231325456468789");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： privateKey is new privateKey.
     * 
     */
    @Test
    public void testRegisterCptCase13() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey()
            .setPrivateKey(TestBaseUtil.createEcKeyPair().getPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： privateKey is SDK privateKey.
     */
    @Test
    public void testRegisterCptCase14() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey(privateKey);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： privateKey is xxxxxxxxx.
     */
    @Test
    public void testRegisterCptCase15() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().getWeIdPrivateKey().setPrivateKey("xxxxxxxxxx");

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptPublisher is not exists and the private key is match.
     * 
     */
    @Test
    public void testRegisterCptCase16() {

        PasswordKey passwordKey = TestBaseUtil.createEcKeyPair();
        String weId = WeIdUtils.convertPublicKeyToWeId(passwordKey.getPublicKey());

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.getWeIdAuthentication().setWeId(weId);
        cptMapArgs.getWeIdAuthentication()
            .getWeIdPrivateKey()
            .setPrivateKey(passwordKey.getPrivateKey());

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.CPT_PUBLISHER_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： mock an InterruptedException.
     */
    @Test
    public void testRegisterCptCase17() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        MockUp<Future<?>> mockFuture = mockInterruptedFuture();

        ResponseData<CptBaseInfo> response = registerCptForMock(cptMapArgs, mockFuture);

        Assert.assertEquals(ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： mock an TimeoutException.
     */
    @Test
    public void testRegisterCptCase18() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        MockUp<Future<?>> mockFuture = mockTimeoutFuture();

        ResponseData<CptBaseInfo> response = registerCptForMock(cptMapArgs, mockFuture);

        Assert.assertEquals(ErrorCode.TRANSACTION_TIMEOUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    private ResponseData<CptBaseInfo> registerCptForMock(
        CptMapArgs cptMapArgs,
        MockUp<Future<?>> mockFuture) {
        
        MockUp<CptController> mockTest = new MockUp<CptController>() {
            @Mock
            public Future<?> registerCpt(
                Address publisher,
                StaticArray<Int256> intArray,
                StaticArray<Bytes32> bytes32Array,
                StaticArray<Bytes32> jsonSchemaArray,
                Uint8 v,
                Bytes32 r,
                Bytes32 s) {
                return mockFuture.getMockInstance();
            }
        };

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        mockTest.tearDown();
        mockFuture.tearDown();
        return response;
    }

    /** 
     * case： mock returns null.
     */
    @Test
    public void testRegisterCptCase19() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);

        MockUp<CptController> mockTest = new MockUp<CptController>() {
            @Mock
            public List<RegisterCptRetLogEventResponse> getRegisterCptRetLogEvents(
                TransactionReceipt transactionReceipt) {
                return null;
            }
        };

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        mockTest.tearDown();

        Assert.assertEquals(
            ErrorCode.CPT_EVENT_LOG_NULL.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string.
     */
    @Test
    public void testRegisterCptCase20() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： build cpt string, args is null.
     */
    @Test
    public void testRegisterCptCase21() {

        CptStringArgs cptStringArgs = null;
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string for unkonw_error.
     */
    @Test
    public void testRegisterCptCase22() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, false);
        cptStringArgs.setCptJsonSchema("xxxxx");
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.UNKNOW_ERROR.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case： build cpt string by file.
     */
    @Test
    public void testRegisterCptCase23() throws IOException {

        CptStringArgs cptStringArgs =
            TestBaseUtil.buildCptStringArgs(createWeId, true);
        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptStringArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case： cptPublisher is blank.
     */
    @Test
    public void testRegisterCptCase27() {

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeId);
        cptMapArgs.setWeIdAuthentication(null);

        ResponseData<CptBaseInfo> response = cptService.registerCpt(cptMapArgs);
        logger.info("registerCpt result:");
        BeanUtil.print(response);

        Assert.assertEquals(
            ErrorCode.WEID_AUTHORITY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    @Test
    public void testRegisterCptCase28() throws Exception {

        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream ksInputStream =
            TestRegisterCpt.class.getClassLoader().getResourceAsStream("tb.jks");
        ks.load(ksInputStream, "123456".toCharArray());
        Key key = ks.getKey("ec", "123456".toCharArray());
        ECPrivateKey privateKey = (ECPrivateKey) key;
        Credentials credentials = Credentials.create(ECKeyPair.create(privateKey.getS()));

        Random r = new SecureRandom();
        BigInteger nonce = new BigInteger(250, r);
        System.out.println("==nonce:" + nonce);

        JsonNode jsonNode = JsonLoader.fromResource("/cpt.json");
        String jsonSchema = jsonNode.toString();
        Map<String, Object> jsonSchemaMap =
            (Map<String, Object>) JsonUtil.jsonStrToObj(new HashMap<String, Object>(), jsonSchema);
        String data =
            createFuntionRegisterCpt(jsonSchemaMap, credentials.getEcKeyPair().getPrivateKey());

        BigInteger blockLimit = web3j.getBlockNumberCache();
        RawTransaction rawTransaction  = RawTransaction.createTransaction(
            nonce,
            new BigInteger("99999999999"),
            new BigInteger("99999999999"),
            blockLimit,
            "0xd7a617780dd61be1c599f2462667a26cbb9fd6bf",
            new BigInteger("0"),
            data,
            TransactionConstant.callType,
            false);

        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        System.out.println("====signedMessage:" + new String(signedMessage, "UTF-8"));
        String hexValue = Hex.toHexString(signedMessage);
        System.out.println("====hexValue:" + hexValue);

        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(jsonSchemaMap.get("weId").toString());

        CptMapArgs args = new CptMapArgs();
        args.setWeIdAuthentication(weIdAuthentication);
        args.setCptJsonSchema((HashMap<String, Object>)jsonSchemaMap.get("cptJsonSchema"));

        ResponseData<CptBaseInfo> response = cptService.registerCpt(args, hexValue);
        System.out.println("====response:" + JsonUtil.objToJsonStr(response));

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        Assert.assertNotNull("hellworld");
    }

    private String createFuntionRegisterCpt(
        Map<String, Object> map,
        BigInteger privateKey) throws Exception {

        String weId = map.get("weId").toString();
        Map<String, Object> cptJsonSchema = (Map<String, Object>) map.get("cptJsonSchema");
        String cptJsonSchemaNew = this.cptSchemaToString(cptJsonSchema);
        RsvSignature rsvSignature = sign(
            weId,
            cptJsonSchemaNew,
            privateKey.toString());

        StaticArray<Bytes32> bytes32Array = DataTypetUtils.stringArrayToBytes32StaticArray(
            new String[WeIdConstant.STRING_ARRAY_LENGTH]
        );


        List<Type> inputParameters = Arrays.<Type>asList(
            new Address(WeIdUtils.convertWeIdToAddress(weId)),
            this.getParamCreated(),
            bytes32Array,
            this.getParamJsonSchema(cptJsonSchemaNew),
            rsvSignature.getV(),
            rsvSignature.getR(),
            rsvSignature.getS());

        Function function = new Function("registerCpt", inputParameters, Collections.emptyList());
        return FunctionEncoder.encode(function);
    }

    private RsvSignature sign(
        String cptPublisher,
        String jsonSchema,
        String privateKey) throws Exception {

        StringBuilder sb = new StringBuilder();
        sb.append(cptPublisher);
        sb.append("|");
        sb.append(jsonSchema);
        SignatureData signatureData =
            SignatureUtils.signMessage(sb.toString(), privateKey);

        Uint8 v = DataTypetUtils.intToUnt8(Integer.valueOf(signatureData.getV()));
        Bytes32 r = DataTypetUtils.bytesArrayToBytes32(signatureData.getR());
        Bytes32 s = DataTypetUtils.bytesArrayToBytes32(signatureData.getS());

        RsvSignature rsvSignature = new RsvSignature();
        rsvSignature.setV(v);
        rsvSignature.setR(r);
        rsvSignature.setS(s);
        return rsvSignature;
    }

    private String cptSchemaToString(Map<String, Object> cptJsonSchema) throws Exception {

        Map<String, Object> cptJsonSchemaNew = new HashMap<String, Object>();
        cptJsonSchemaNew.put(JsonSchemaConstant.SCHEMA_KEY, JsonSchemaConstant.SCHEMA_VALUE);
        cptJsonSchemaNew.put(JsonSchemaConstant.TYPE_KEY, JsonSchemaConstant.DATE_TYPE_OBJECT);
        cptJsonSchemaNew.putAll(cptJsonSchema);
        return JsonUtil.objToJsonStr(cptJsonSchemaNew);
    }

    private StaticArray<Int256> getParamCreated() {

        long[] longArray = new long[WeIdConstant.LONG_ARRAY_LENGTH];
        long created = System.currentTimeMillis();
        longArray[1] = created;
        return DataTypetUtils.longArrayToInt256StaticArray(longArray);
    }

    private StaticArray<Bytes32> getParamJsonSchema(String cptJsonSchemaNew) {

        List<String> stringList = Splitter
            .fixedLength(WeIdConstant.BYTES32_FIXED_LENGTH)
            .splitToList(cptJsonSchemaNew);
        String[] jsonSchemaArray = new String[WeIdConstant.JSON_SCHEMA_ARRAY_LENGTH];
        for (int i = 0; i < stringList.size(); i++) {
            jsonSchemaArray[i] = stringList.get(i);
        }
        return DataTypetUtils.stringArrayToBytes32StaticArray(jsonSchemaArray);
    }

}
