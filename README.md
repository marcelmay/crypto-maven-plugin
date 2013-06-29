Maven Crypto Plugin
==================================

The plugin *crypto-maven-plugin* lets you encrypt and decrypt artifacts.


What is it good for?
--------------------

* Encrypt generated artefacts

Check out the [plugin web site][site] for details.

[site]: http://labs.consol.de/projects/maven/crypt-maven-plugin/

Development
-----------

* Build the plugin

    mvn clean install

  Make sure you got [Maven 3.0.3+][maven_download] or higher.

* Build the site (and the optional example report)

    mvn clean install integration-test site -Psite

    mvn site:deploy -Psite,dist-labs

* Release

    mvn release:prepare

    mvn release:perform

Make sure you got the changes etc for the site updated previous to the release.

[maven_download]: http://maven.apache.org
