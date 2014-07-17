package net.ripe.db.whois.common.rpsl.impl;

import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

@ContextConfiguration(locations = {"classpath:applicationContext-object.xml"})
public class RipeObjectTypeFactoryIntegrationTest extends AbstractJUnit4SpringContextTests {
    @Autowired ApplicationContext applicationContext;
    @Autowired IObjectTypeFactory objectTypeFactory;

    @Test
    public void testBasic() {
        Assert.assertNotNull(objectTypeFactory);
        Assert.assertNotNull(objectTypeFactory.get("as-set"));
    }
}
