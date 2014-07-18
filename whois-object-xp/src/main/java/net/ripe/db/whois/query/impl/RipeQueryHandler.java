package net.ripe.db.whois.query.impl;

import com.google.common.collect.Maps;
import net.ripe.db.whois.query.*;
import org.apache.commons.cli.*;

import javax.inject.Inject;
import java.io.IOException;
import java.io.OutputStream;
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

    private void initQueryParser() {
        options = new Options();
        options.addOption("help", false, "Help");
        options.addOption("T", true, "Object type");
        options.addOption("i", true, "Inverse key lookup");
        parser = new BasicParser();
    }

    @Override
    public IQuery parse(String query) {

        // Command line parsing
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, query.split("\\s"));
        } catch (ParseException e) {
            e.printStackTrace(); // TODO log and throw exception
            return null;
        }

        // Selecting specialized query executor
        IQueryExecutor queryExecutor = ripeAsnumQueryExecutor;
        for (Option option: cmd.getOptions()) {
            String opt = option.getOpt();
            if (opt.equals("help")) {
                queryExecutor = ripeHelpQueryExecutor;
            }
        }

        // Setting command line arguments in selected query executor
        IQuery queryHolder = (IQuery) queryExecutor;
        for (Option option: cmd.getOptions()) {
            String opt = option.getOpt();
            queryHolder.setArgValue(opt, cmd.getOptionValue(opt));
        }

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
                return "\n" + queryResponse.toString() + "\nRIPE NCC";
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
}
