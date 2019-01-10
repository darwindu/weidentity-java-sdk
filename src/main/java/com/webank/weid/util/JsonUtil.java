package com.webank.weid.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import com.webank.weid.exception.DataTypeCastException;

/**
 * data type cast by jackson method.
 * @author darwindu
 */
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
            // pojo sort by alphabetically
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY,true);
            // when map is serialization, sort by key
            mapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS,true);
            return mapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new DataTypeCastException(e);
        }
    }
}
