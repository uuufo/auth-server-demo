package dev.jlarsen.authserverdemo.config;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
class EmbeddedCacheConfig {

    @Bean
    Config config() {
        Config config = new Config();
        // we only cache auth codes for 3 minutes (until they expire)
        MapConfig mapConfig = new MapConfig();
        mapConfig.setTimeToLiveSeconds(180);
        config.getMapConfigs().put("codes", mapConfig);

        return config;
    }
}