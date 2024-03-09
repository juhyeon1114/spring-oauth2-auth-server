package study.springoauth2authserver.asserttest;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.util.Assert;

import java.util.*;

@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AssertTest {

    @Test
    @DisplayName("assertTest")
    public void assertTest() throws Exception {
        try {
            assert 1 == 2 : "bye";
        } catch (AssertionError e) {
            log.info("Catch : {}", e.getMessage());
        }

        log.info("Done");
    }

    @Test
    @DisplayName("AssertionTest")
    public void AssertionTest() throws Exception {
        // Logical assertions
        try {
            Assert.isTrue(1 == 2, "isTrue");
        } catch (IllegalArgumentException e) {}

        try {
            Assert.state(1 == 2, "state");
        } catch (IllegalStateException e) {}

        // Object and type assertions
        String hello = "world";
        Assert.notNull(hello, "notNull");

        Assert.isNull(null, "isNull");

        String text = "text";
        Assert.isInstanceOf(String.class, text);

        Assert.isAssignable(AbstractMap.class, HashMap.class);

        // Text assertions
        String noBlank = " ";
        Assert.hasLength(noBlank, "hasLength");

        String hasText = "abc";
        Assert.hasText(hasText, "hasText");

        String abc = "abc";
        Assert.doesNotContain("a", abc, "doesNotContain");

        // Collection and map assertions
        Collection<Integer> list = List.of(1);
        Assert.notEmpty(list, "notEmpty");

        HashMap<String, String> hashMap = new HashMap();
        hashMap.put("hello", "world");
        Assert.notEmpty(hashMap, "notEmpty");

        // Array assertions
        Integer[] numbers = new Integer[1];
        numbers[0] = 1;
        Assert.notEmpty(numbers, "notEmpty");

        Assert.noNullElements(numbers, "noNullElements");
    }

}
