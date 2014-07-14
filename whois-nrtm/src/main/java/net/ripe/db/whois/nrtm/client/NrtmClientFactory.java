package net.ripe.db.whois.nrtm.client;


import com.google.common.util.concurrent.Uninterruptibles;
import net.ripe.db.whois.common.MaintenanceMode;
import net.ripe.db.whois.common.aspects.RetryFor;
import net.ripe.db.whois.common.dao.RpslObjectUpdateDao;
import net.ripe.db.whois.common.dao.RpslObjectUpdateInfo;
import net.ripe.db.whois.common.dao.SerialDao;
import net.ripe.db.whois.common.domain.Operation;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.source.Source;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.nrtm.dao.NrtmClientDao;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.SocketChannel;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
class NrtmClientFactory {
    private static final Pattern OPERATION_AND_SERIAL_PATTERN = Pattern.compile("^(ADD/UPD|DEL)[ ](\\d+)$");

    private static final Logger LOGGER = LoggerFactory.getLogger(NrtmClientFactory.class);

    private final SourceContext sourceContext;
    private final SerialDao serialDao;
    private final RpslObjectUpdateDao rpslObjectUpdateDao;
    private final NrtmClientDao nrtmClientDao;
    private final MaintenanceMode maintenanceMode;

    @Autowired
    public NrtmClientFactory(final SourceContext sourceContext,
                             final SerialDao serialDao,
                             final RpslObjectUpdateDao rpslObjectUpdateDao,
                             final NrtmClientDao nrtmClientDao,
                             final MaintenanceMode maintenanceMode) {
        this.sourceContext = sourceContext;
        this.serialDao = serialDao;
        this.rpslObjectUpdateDao = rpslObjectUpdateDao;
        this.nrtmClientDao = nrtmClientDao;
        this.maintenanceMode = maintenanceMode;
    }

    public NrtmClient createNrtmClient(final NrtmSource nrtmSource) {
        return new NrtmClient(nrtmSource);
    }

    public class NrtmClient implements Runnable {
        private final NrtmSource nrtmSource;

        private SocketChannel socketChannel;
        private SocketChannelFactory.Reader reader;
        private SocketChannelFactory.Writer writer;

        public NrtmClient(final NrtmSource nrtmSource) {
            this.nrtmSource = nrtmSource;
        }

        @Override
        public void run() {
            try {
                sourceContext.setCurrent(Source.master(nrtmSource.getName()));

                while (true) {
                    try {
                        connect();
                        reader = SocketChannelFactory.createReader(socketChannel);
                        writer = SocketChannelFactory.createWriter(socketChannel);

                        readHeader();
                        writeMirrorCommand();
                        readMirrorResult();
                        readUpdates();
                    } catch (ClosedByInterruptException e) {
                        LOGGER.info("Interrupted, stopping.");
                        break;
                    } catch (IllegalStateException e) {
                        LOGGER.error(e.getMessage());
                        break;
                    } catch (IOException ignored) {
                        // retry
                    } catch (RuntimeException e) {
                        LOGGER.info("Caught exception while connected, ignoring.", e);
                    } finally {
                        IOUtils.closeQuietly(socketChannel);
                    }
                }
            } finally {
                sourceContext.removeCurrentSource();
            }
        }

        @RetryFor(value = IOException.class, attempts = 100, intervalMs = 10 * 1000)
        private void connect() throws IOException {
            try {
                socketChannel = SocketChannelFactory.createSocketChannel(nrtmSource.getHost(), nrtmSource.getPort());
                LOGGER.info("Connected to {}:{}", nrtmSource.getHost(), nrtmSource.getPort());
            } catch (UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        }

        private void readHeader() throws IOException {
            readLineWithExpected("%");
            readLineWithExpected("%");
            readEmptyLine();
        }

        private String readLineWithExpected(final String expected) throws IOException {
            final String line = reader.readLine();
            if (!line.contains(expected)) {
                throw new IllegalStateException("Expected to read: \"" + expected + "\", but actually read: \"" + line + "\"");
            }
            return line;
        }

        private String readEmptyLine() throws IOException {
            final String line = reader.readLine();
            if (!StringUtils.isBlank(line)) {
                throw new IllegalStateException("Expected to read empty line, but actually read: \"" + line + "\"");
            }

            return line;
        }

        private void writeMirrorCommand() throws IOException {
            final String mirrorCommand = String.format("-g %s:3:%d-LAST -k",
                    nrtmSource.getOriginSource(),
                    serialDao.getSerials().getEnd());

            writeLine(mirrorCommand);
        }

        private void readMirrorResult() throws IOException {
            final String result = readLineWithExpected("%START");
            readEmptyLine();
            LOGGER.info(result);
        }

        private void writeLine(final String line) throws IOException {
            writer.writeLine(line);
        }

        private void readUpdates() throws IOException {
            while (true) {
                if (maintenanceMode.allowUpdate()) {
                    final OperationSerial operationSerial = readOperationAndSerial();
                    final RpslObject object = readObject();
                    update(operationSerial.getOperation(), operationSerial.getSerial(), object);
                } else {
                    Uninterruptibles.sleepUninterruptibly(1, TimeUnit.SECONDS);
                }
            }
        }

        public void update(final Operation operation, final int serialId, final RpslObject rpslObject) {
            try {
                switch (operation) {
                    case UPDATE:
                        try {
                            final RpslObjectUpdateInfo updateInfo = rpslObjectUpdateDao.lookupObject(rpslObject.getType(), rpslObject.getKey().toString());
                            if (!nrtmClientDao.objectExistsWithSerial(serialId, updateInfo.getObjectId())) {
                                nrtmClientDao.updateObject(rpslObject, updateInfo, serialId);
                            }
                        } catch (EmptyResultDataAccessException e) {
                            nrtmClientDao.createObject(rpslObject, serialId);
                        }
                        break;

                    case DELETE:
                        try {
                            final RpslObjectUpdateInfo updateInfo = rpslObjectUpdateDao.lookupObject(rpslObject.getType(), rpslObject.getKey().toString());
                            if (!nrtmClientDao.objectExistsWithSerial(serialId, updateInfo.getObjectId())) {
                                nrtmClientDao.deleteObject(updateInfo, serialId);
                            }
                        } catch (EmptyResultDataAccessException e) {
                            throw new IllegalStateException("DELETE serial:" + serialId + " but object:" + rpslObject.getKey().toString() + " doesn't exist");
                        }
                        break;
                }
            } catch (DataAccessException e) {
                throw new IllegalStateException("Unexpected error on " + operation + " " + serialId, e);
            }
        }

        private OperationSerial readOperationAndSerial() throws IOException {
            final String line = readLineWithExpected(" ");

            final Matcher matcher = OPERATION_AND_SERIAL_PATTERN.matcher(line);
            if (!matcher.find()) {
                throw new IllegalStateException("Unexpected response from NRTM server: \"" + line + "\"");
            }

            final Operation operation = Operation.getByName(matcher.group(1));
            final String serial = matcher.group(2);
            readEmptyLine();
            return new OperationSerial(operation, serial);
        }

        private RpslObject readObject() throws IOException {
            StringBuilder builder = new StringBuilder();
            String line;
            while (!(line = reader.readLine()).isEmpty()) {
                builder.append(line);
                builder.append('\n');
            }
            return RpslObject.parse(builder.toString());
        }

        private final class OperationSerial {
            private final Operation operation;
            private final int serial;

            private OperationSerial(final Operation operation, final String serial) {
                this.operation = operation;
                this.serial = Integer.parseInt(serial);
            }

            private Operation getOperation() {
                return operation;
            }

            private int getSerial() {
                return serial;
            }
        }
    }
}
