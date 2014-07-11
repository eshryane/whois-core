package net.ripe.db.whois.common.dao;

public interface IndexDao {
    void rebuild();

    void rebuildForObject(int objectId);

    void pause();

    void resume();
}
