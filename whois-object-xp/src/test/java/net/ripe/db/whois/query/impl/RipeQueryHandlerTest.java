package net.ripe.db.whois.query.impl;

import net.ripe.db.whois.query.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.IOException;
import java.io.OutputStream;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.verify;

/**
 * Created by yogesh on 7/17/14.
 */
@RunWith(MockitoJUnitRunner.class)
public class RipeQueryHandlerTest {

    @Spy
    private IQueryExecutor ripeAsnumQueryExecutor = new RipeAsnumQueryExecutor();;

    @Spy
    private IQueryExecutor ripeHelpQueryExecutor = new RipeHelpQueryExecutor();

    @Spy
    private OutputStream out = System.out;

    @InjectMocks
    private RipeQueryHandler subject = new RipeQueryHandler();

    @Before
    public void initMocks() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testAutnum() throws IOException {
        subject.handle("-T aut-num");
        verify(out).write((byte[]) anyObject());
    }

    @Test
    public void testHelp() throws IOException {
        subject.handle("-help");
        verify(out).write((byte[]) anyObject());
    }
}
