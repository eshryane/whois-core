package net.ripe.db.whois.query.impl;

import com.google.common.collect.Maps;
import net.ripe.db.whois.query.*;
import org.apache.commons.cli.*;

import javax.inject.Inject;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

/**
 * Created by yogesh on 7/17/14.
 */
public class RipeQueryHandler
        extends AbstractQueryHandler
        implements IQueryHandler, IQueryParser, IQueryExecutorFactory, IQueryResponsePublisher {


    private Options options;

    private CommandLineParser parser;

    private Map<String,String> optionValueMap = Maps.newHashMap();

    private Collection<IQueryResponsePublisher> publishers = Arrays.asList((IQueryResponsePublisher) this);

    @Inject
    private IQueryExecutor ripeAsnumQueryExecutor;

    @Inject
    private IQueryExecutor ripeHelpQueryExecutor;

    @Inject
    private OutputStream out;

    public RipeQueryHandler() {
        initQueryParser();
    }

    @Override
    public IQuery parse(String query) {

        // Command line parsing
        String key = null;
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, query.split("\\s"));
        } catch (ParseException e) {
            e.printStackTrace(); // TODO log and throw exception
            return null;
        }
        String[] args = cmd.getArgs();
        if (args.length > 0) {
            key = args[0];
        }

        // Selecting specialized query executor
        IQueryExecutor queryExecutor = getQueryExecutor(key);

        // Setting command line arguments in selected query executor
        IQuery queryHolder = (IQuery) queryExecutor;
        populate(queryHolder, key, cmd);

        return queryHolder;
    }

    /**
     * Allow registering additional publishers
     * e.g a Netty channel upstream handler or RESTful service.
     * @param publisher
     */
    public void registerPublisher(IQueryResponsePublisher publisher) {
        publishers.add(publisher);
    }

    @Override
    public void publish(IQueryResponse queryResponse) {
        try {
            out.write(queryResponse.toString().getBytes());
        } catch (IOException e) {
            e.printStackTrace(); // TODO log and throw exception
        }
    }

    @Override
    protected IQueryResponse modifyQueryResponse(final IQueryResponse queryResponse) {
        return super.modifyQueryResponse(new IQueryResponse() {
            @Override
            public String toString() {
                return "\n[ header ]\n" + queryResponse.toString() + "\n[ footer ]";
            }
        });
    }

    @Override
    public IQueryExecutor getQueryExecutor(IQuery query) {
        return (IQueryExecutor) query;
    }


    @Override
    protected IQueryParser getQueryParser() {
        return this;
    }

    @Override
    protected IQueryExecutorFactory getQueryExecutorFactory() {
        return this;
    }

    @Override
    protected Collection<IQueryResponsePublisher> getQueryResponsePublishers() {
        return publishers;
    }

    private void initQueryParser() {
        options = new Options();
        options.addOption(
                OptionBuilder.withArgName("type")
                        .hasArg()
                        .withDescription("Object type")
                        .create("T")
        );
        options.addOption(
                OptionBuilder.withArgName("inverse key")
                        .hasArg()
                        .withDescription("Inverse key lookup")
                        .create("i")
        );

        parser = new BasicParser();

    }

    private void initHelpText() {
        HelpFormatter formatter = new HelpFormatter();
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        formatter.printHelp(pw, 100, "whois [options] [key]", "", options, 4, 4, "");
        ((RipeHelpQueryExecutor) ripeHelpQueryExecutor).setHelpText(sw.toString());
    }

    private IQueryExecutor getQueryExecutor(String key) {
        IQueryExecutor queryExecutor = null;
        Collection<IQueryExecutor> queryExecutors =
                Arrays.asList(ripeHelpQueryExecutor, ripeAsnumQueryExecutor); // FIXME initialize elsewhere
        for (IQueryExecutor ripeQueryExecutor: queryExecutors) {
            if (ripeQueryExecutor.supports(key)) {
                queryExecutor = ripeQueryExecutor;
                break;
            }
        }

        if (queryExecutor == null) {
            throw new UnsupportedOperationException("Verify your query syntax");
        }

        return queryExecutor;
    }

    private void populate(IQuery queryHolder, String key, CommandLine cmd) {
        queryHolder.setKey(key);
        for (Option option: cmd.getOptions()) {
            String opt = option.getOpt();
            queryHolder.setOptionValue(opt, cmd.getOptionValue(opt));
        }

        // Init help text
        if (queryHolder == ripeHelpQueryExecutor) {
            initHelpText(); // FIXME initialize elsewhere
        }
    }
}
