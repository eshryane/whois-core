package net.ripe.db.whois.common.rpsl;

import net.ripe.db.whois.common.rpsl.attributetype.AttributeType;
import net.ripe.db.whois.common.rpsl.attributetype.impl.AttributeTypes;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class AttributeTypeTest {
    @Test
    public void getByName() {
        for (AttributeType attributeType : AttributeTypes.values()) {
            assertThat("by name " + attributeType.toString(), AttributeTypes.getByName(attributeType.getName()), is(attributeType));
            assertThat("by flag " + attributeType.toString(), AttributeTypes.getByName(attributeType.getFlag()), is(attributeType));
        }
    }

    @Test
    public void getByNameOrNull() {
        for (AttributeType attributeType : AttributeTypes.values()) {
            assertThat("by name " + attributeType.toString(), AttributeTypes.getByNameOrNull(attributeType.getName()), is(attributeType));
            assertThat("by flag " + attributeType.toString(), AttributeTypes.getByNameOrNull(attributeType.getFlag()), is(attributeType));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void getByName_throws_on_unknown() {
        AttributeTypes.getByName("BOOOYAKAAAA!!!");
    }

    @Test
    public void getByNameOrNull_supports_shortkeys() {
        assertThat(AttributeTypes.getByNameOrNull("*as"), is(AttributeTypes.AS_SET));
    }
}
