// IFirewall.aidl
package eu.faircode.netguard;

// Declare any non-default types here with import statements

interface IFirewall {
    /**
     * Demonstrates some basic types that you can use as parameters
     * and return values in AIDL.
     */

      void controlDataOfPackage(String aString);

      void revokePolicy(String aString);

      void start();
}
