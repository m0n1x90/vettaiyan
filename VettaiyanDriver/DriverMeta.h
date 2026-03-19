#ifndef DRIVER_META_H
#define DRIVER_META_H

/*
 * DriverMeta.h -- driver identity and registration constants.
 *
 * These values identify the driver to the OS, define the device
 * path the agent uses to communicate with us, and set our altitude
 * for callback registration ordering.
 */

/* Display name -- shown in driver manager and debug output */
#define EDR_NAME L"Vettaiyan EDR"

/* Device object path (kernel namespace) and symbolic link (user-visible).
   The agent opens \\.\VettaiyanEDR to send IOCTLs. */
#define EDR_DEVICE_NAME L"\\Device\\VettaiyanEdrDevice"
#define EDR_SYMLINK_NAME L"\\??\\VettaiyanEDR"

/* Altitude for minifilter and callback registration.
   Determines our position in the callback stack relative to other
   drivers. Higher = called earlier. 369010 puts us in the
   "FSFilter Anti-Virus" range (360000-389999). */
#define DRIVER_ALTITUDE L"369000"

#endif