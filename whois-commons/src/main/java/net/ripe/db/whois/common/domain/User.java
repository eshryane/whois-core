package net.ripe.db.whois.common.domain;

import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.rpsl.IObjectType;
import org.springframework.util.DigestUtils;

import java.util.Collections;
import java.util.Set;

import static net.ripe.db.whois.common.domain.CIString.ciString;

public final class User {
    private final CIString username;
    private final String hashedPassword;
    private final Set<IObjectType> objectTypes;

    private User(final CIString username, final String hashedPassword, final Set<IObjectType> objectTypes) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.objectTypes = Collections.unmodifiableSet(objectTypes);
    }

    public CIString getUsername() {
        return username;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    public Set<IObjectType> getIObjectTypes() {
        return objectTypes;
    }

    public boolean isValidPassword(final String password) {
        return getHash(password).equals(hashedPassword);
    }

    public static User createWithPlainTextPassword(final String username, final String password, final IObjectType... objectTypes) {
        return new User(ciString(username), getHash(password), Sets.newEnumSet(Lists.newArrayList(objectTypes), IObjectType.class));
    }

    public static User createWithHashedPassword(final String username, final String hashedPassword, final Iterable<IObjectType> objectTypes) {
        return new User(ciString(username), hashedPassword, Sets.newEnumSet(objectTypes, IObjectType.class));
    }

    private static String getHash(final String text) {
        return DigestUtils.md5DigestAsHex(text.getBytes(Charsets.UTF_8));
    }
}
