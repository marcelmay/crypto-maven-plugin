Maven Crypto Plugin
==================================

The plugin *crypto-maven-plugin* lets you encrypt and decrypt resources.

What is it good for?
--------------------

* Encrypt generated resources

Check out the [plugin web site][site] for details.

[site]: http://marcelmay.github.io/crypto-maven-plugin/
[repo-snapshot]: https://oss.sonatype.org/content/repositories/snapshots/de/m3y/maven/crypto-maven-plugin/

Development
-----------

* Build the plugin

    mvn clean install

  Make sure you got [Maven 3.0.3+][maven_download] or higher.

* Build the site

    mvn clean install integration-test site -Psite

* Release

    mvn release:prepare -Prelease

    mvn release:perform -Prelease

* Deploy snapshot

    mvn clean deploy -Prelease

  Note: The release profile contains the snapshot repository for distribution management

[maven_download]: http://maven.apache.org
