package org.logstash.secret.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.logstash.secret.cli.SecretStoreCli;
import org.logstash.secret.cli.Terminal;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class SecretStoreMain {
    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        SecretStoreCli cli = new SecretStoreCli(new Terminal());
        int pos = 0;
        int foundPos = -1;
        for(String arg : args){
            if (arg.equals("--path.settings")){
                foundPos = pos;
                break;
            }
            pos++;
        }
        Path filePath = Paths.get(System.getenv("LOGSTASH_HOME")).resolve("config");
        if (foundPos != -1) {
            filePath = Paths.get(args[foundPos + 1]).resolve("config");
        }

        Path pathToConfig = filePath.resolve("logstash.yml");
        ObjectMapper om = new ObjectMapper(new YAMLFactory());
        Map<String, String> settings = om.readValue(pathToConfig.toFile(), Map.class);
        String keystoreFile = settings.getOrDefault("keystore.file", filePath.resolve("logstash.keystore").toString());
        String keystoreClass = settings.getOrDefault("keystore.class", "org.logstash.secret.store.backend.JavaKeyStore");
        SecureConfig secureConfig = SecretStoreExt.getConfig(keystoreFile, keystoreClass);
        cli.command(args[0], secureConfig, args.length > 1 ? args[1] : null);
    }
}
