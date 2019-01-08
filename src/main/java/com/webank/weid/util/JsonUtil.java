package com.webank.weid.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.webank.weid.exception.DataTypeCastException;

public class JsonUtil {

    /**
     * Json String to Object.
     * @param obj Object
     * @param jsonStr Json String
     * @return Object
     */
    public static Object jsonStrToObj(Object obj, String jsonStr) {

        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(jsonStr, obj.getClass());
        } catch (IOException e) {
            throw new DataTypeCastException(e);
        }
    }

    /**
     * Object to Json String.
     * @param obj Object
     * @return String
     */
    public static String objToJsonStr(Object obj) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new DataTypeCastException(e);
        }
    }
}
