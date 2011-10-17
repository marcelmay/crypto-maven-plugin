package net.metacube.maven.crypto;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.FileSet;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.DirectoryScanner;
import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.io.FileInputStreamFacade;

/**
 * Supports de- and encryption of artifacts.
 *
 * @goal crypto
 * @threadSafe
 */
public class MavenCryptoMojo extends AbstractMojo {
    /**
     * @parameter expression="${project}"
     */
    MavenProject project;
    /**
     * @parameter default-value="${session}"
     * @readonly
     * @required
     */
    protected MavenSession session;
    /**
     * List of file sets.
     *
     * @parameter
     * @required
     */
    List<FileSet> fileSets;

    /**
     * Directory containing the generated JAR.
     *
     * @parameter default-value="${project.build.directory}"
     * @required
     */
    private File outputDirectory;

    public enum CipherOperationMode {
        encrypt(Cipher.ENCRYPT_MODE), decrypt(Cipher.DECRYPT_MODE);

        private int mode;
        private CipherOperationMode(int pMode) {
            mode = pMode;
        }
        public int asInt() {
            return mode;
        }
    }

    public static class CipherOptions {
        public CipherOperationMode operationMode;
        public String algorithm;
        public String algorithmMode;
        public String algorithmPadding;
        public String secret;
        public String keyDigest;
        public String initVector;
        public boolean hasInitVector() {
            return null!=initVector && initVector.length()>0;
        }
        public boolean hasAlgorithmMode() {
            return null!=algorithmMode && algorithmMode.length()>0;
        }
        public boolean hasAlgorithmPadding() {
            return null!=algorithmPadding && algorithmPadding.length()>0;
        }
        public boolean hasKeyDigest() {
            return null!=keyDigest && keyDigest.length()>0;
        }
    }

    /**
     * Configures the cipher.
     * <p/>
     * Example (see <a href="http://download.oracle.com/javase/1,5.0/docs/api/javax/crypto/Cipher.html">javax.security.Cipher</a> for details):
     * <pre>
     * &lt;cipherOptions&gt;
     *     &lt;operationMode&gt;encrypt&lt;/operationMode&gt;
     *     &lt;algorithm&gt;AES&lt;/algorithm&gt;
     *     &lt;algorithmMode&gt;CBC&lt;/algorithmMode&gt;
     *     &lt;algorithmPadding&gt;PKCS5Padding&lt;/algorithmPadding&gt;
     *     &lt;secret&gt;metacube&lt;/secret&gt;
     *     &lt;keyDigest&gt;MD5&lt;keyDigest/&gt;
     *     &lt;initVector&gt;5&lt;initVector/&gt;
     * &lt;/cipherOptions&gt;
     * </pre>
     *
     * The keyDigest is recommended, to get a 128bit key.
     *
     * @parameter
     * @required
     */
    private CipherOptions cipherOptions;

    public void execute() throws MojoExecutionException, MojoFailureException {
        Cipher cipher = createCipher();
        try {
            for (FileSet fileSet : getFileSets()) {
                handle(fileSet, cipher);
            }
        } catch (IOException e) {
            throw new MojoFailureException("Failed to execute", e);
        }
    }

    private Cipher createCipher() throws MojoFailureException {
        CipherOptions options = getCipherOptions();
        try {
            byte[] key = getCipherKey(options);

            SecretKeySpec skeySpec = new SecretKeySpec(key, options.algorithm);
            String algorithmSpec = options.algorithm;
            if(options.hasAlgorithmMode()) {
                algorithmSpec += '/' + options.algorithmMode;
            }
            if(options.hasAlgorithmPadding()) {
                algorithmSpec += '/' + options.algorithmPadding;
            }
            if (getLog().isDebugEnabled()) {
                getLog().debug("Using algorithm "+algorithmSpec);
            }

            Cipher cipher = Cipher.getInstance(algorithmSpec);
            if(options.hasInitVector()) {
                cipher.init(options.operationMode.asInt(), skeySpec,
                        new IvParameterSpec(DatatypeConverter.parseBase64Binary(options.initVector)));
            } else {
                cipher.init(options.operationMode.asInt(), skeySpec);
            }
            return cipher;
        } catch (InvalidKeyException e) {
            throw new MojoFailureException("Invalid cipher key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new MojoFailureException("No such cipher algorithm "+options.algorithm, e);
        } catch (NoSuchPaddingException e) {
            throw new MojoFailureException("No such cipher padding "+options.algorithmPadding, e);
        } catch (UnsupportedEncodingException e) {
            throw new MojoFailureException("Unsupported encoded ", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new MojoFailureException("Invalid algorithm paramter ", e);
        }
    }

    private byte[] getCipherKey(final CipherOptions pOptions) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] key;
        if(pOptions.hasKeyDigest()) {
            getLog().info("Using "+ pOptions.keyDigest+" digest of secret key");
            final MessageDigest digest = MessageDigest.getInstance(pOptions.keyDigest);
            digest.reset();
            digest.update(pOptions.secret.getBytes("UTF8"));
            key = digest.digest();
        } else {
            key = pOptions.secret.getBytes("UTF8");
        }
        return key;
    }

    private void handle(final FileSet pFileSet, final Cipher pCipher) throws IOException {
        DirectoryScanner s = new DirectoryScanner();
        s.setBasedir(pFileSet.getDirectory());
        // By default include everything, if no includes are set
        if (pFileSet.getIncludes().size() == 0) {
            pFileSet.getIncludes().add("**/*");
        }
        s.setExcludes(pFileSet.getExcludes().toArray(new String[pFileSet.getExcludes().size()]));
        s.setIncludes(pFileSet.getIncludes().toArray(new String[pFileSet.getIncludes().size()]));
        s.scan();

        File dir = new File(pFileSet.getDirectory());
        CipherOptions options = getCipherOptions();
        String ext = '.' + options.algorithm;
        for (String file : s.getIncludedFiles()) {
            String targetFile = file;
            if(targetFile.endsWith(ext)) {
                targetFile = targetFile.substring(0,targetFile.length()-ext.length());
            } else {
                targetFile += ext;
            }
            handleFile(new File(dir, file), new File(getOutputDirectory(), targetFile), pCipher);
        }
        if(!options.hasInitVector()) {
            getLog().info("Generated initialization vector is "+ DatatypeConverter.printBase64Binary(pCipher.getIV()));
        }
    }

    private void handleFile(final File pSourceFile, final File pTargetFile, final Cipher pCipher) throws IOException {
        if (getLog().isDebugEnabled()) {
            getLog().debug("Crypting " + pSourceFile + " to " + pTargetFile);
        }
        long time = System.currentTimeMillis();
        FileUtils.copyStreamToFile(new CryptoFileInputStreamFacade(pSourceFile, pCipher), pTargetFile);
        time = System.currentTimeMillis() - time;

        StringBuilder buf = new StringBuilder();
        buf.append(cipherOptions.operationMode==CipherOperationMode.encrypt?"Encrypted ":"Decrypted ");
        buf.append(pSourceFile.getName()).append(" to ").append(pTargetFile.getName()).append(' ');
        while(buf.length()<71) {
            buf.append('.');
        }
        buf.append(" [").append(time).append("ms]");
        getLog().info(buf);
    }

    private static class CryptoFileInputStreamFacade extends FileInputStreamFacade {
        private Cipher cipher;

        public CryptoFileInputStreamFacade(final File pFile, Cipher pCipher) {
            super(pFile);
            cipher = pCipher;
        }

        public InputStream getInputStream() throws IOException {
            return new CipherInputStream(super.getInputStream(), cipher);
        }
    }

    public List<FileSet> getFileSets() {
        return fileSets;
    }

    public File getOutputDirectory() {
        return outputDirectory;
    }

    public CipherOptions getCipherOptions() {
        return cipherOptions;
    }
}
