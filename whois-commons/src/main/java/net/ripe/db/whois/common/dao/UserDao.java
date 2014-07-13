package net.ripe.db.whois.common.dao;

import net.ripe.db.whois.common.rpsl.User;

public interface UserDao {
    User getOverrideUser(String username);
}
