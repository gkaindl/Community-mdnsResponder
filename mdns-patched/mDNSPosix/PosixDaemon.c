/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

	File:		daemon.c

	Contains:	main & associated Application layer for mDNSResponder on Linux.

 */

#if __APPLE__
// In Mac OS X 10.5 and later trying to use the daemon function gives a “‘daemon’ is deprecated”
// error, which prevents compilation because we build with "-Werror".
// Since this is supposed to be portable cross-platform code, we don't care that daemon is
// deprecated on Mac OS X 10.5, so we use this preprocessor trick to eliminate the error message.
#define daemon yes_we_know_that_daemon_is_deprecated_in_os_x_10_5_thankyou
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>

#if __APPLE__
#undef daemon
extern int daemon(int, int);
#endif

#include "mDNSEmbeddedAPI.h"
#include "mDNSPosix.h"
#include "mDNSUNP.h"		// For daemon()
#include "uds_daemon.h"
#include "PlatformCommon.h"

#define CONFIG_FILE "/etc/mdnsd.conf"

// service registration
#define SERVICES_FILE "/etc/mdnsd-services.conf"
static mStatus RegisterServicesInFile(const char *filePath);
static void DeregisterOurServices(void);

static domainname DynDNSZone;                // Default wide-area zone for service registration
static domainname DynDNSHostname;

#define RR_CACHE_SIZE 500
static CacheEntity gRRCache[RR_CACHE_SIZE];
static mDNS_PlatformSupport PlatformStorage;

mDNSlocal void mDNS_StatusCallback(mDNS *const m, mStatus result)
	{
	(void)m; // Unused
	if (result == mStatus_NoError)
		{
		// On successful registration of dot-local mDNS host name, daemon may want to check if
		// any name conflict and automatic renaming took place, and if so, record the newly negotiated
		// name in persistent storage for next time. It should also inform the user of the name change.
		// On Mac OS X we store the current dot-local mDNS host name in the SCPreferences store,
		// and notify the user with a CFUserNotification.
		}
	else if (result == mStatus_ConfigChanged)
		{
		udsserver_handle_configchange(m);
		}
	else if (result == mStatus_GrowCache)
		{
		// Allocate another chunk of cache storage
		CacheEntity *storage = malloc(sizeof(CacheEntity) * RR_CACHE_SIZE);
		if (storage) mDNS_GrowCache(m, storage, RR_CACHE_SIZE);
		}
	}

// %%% Reconfigure() probably belongs in the platform support layer (mDNSPosix.c), not the daemon cde
// -- all client layers running on top of mDNSPosix.c need to handle network configuration changes,
// not only the Unix Domain Socket Daemon

static void Reconfigure(mDNS *m)
	{
	mDNSAddr DynDNSIP;
   const mDNSAddr dummy = { mDNSAddrType_IPv4, { { { 1, 1, 1, 1 } } } };;
   mDNSAddr router;
   mDNS_SetPrimaryInterfaceInfo(m, NULL, NULL, NULL);
	if (ParseDNSServers(m, uDNS_SERVERS_FILE) < 0)
		LogMsg("Unable to parse DNS server list. Unicast DNS-SD unavailable");
	ReadDDNSSettingsFromConfFile(m, CONFIG_FILE, &DynDNSHostname, &DynDNSZone, NULL);
	mDNSPlatformSourceAddrForDest(&DynDNSIP, &dummy);
	if (DynDNSHostname.c[0]) mDNS_AddDynDNSHostName(m, &DynDNSHostname, NULL, NULL);
	if (DynDNSIP.type) {
      int r = mDNS_PlatformGetGateway(NULL, &router, NULL);
      mDNS_SetPrimaryInterfaceInfo(m, &DynDNSIP, NULL, (mStatus_NoError == r) ? &router : NULL);
   }
   
	mDNS_ConfigChanged(m);
	}

// Do appropriate things at startup with command line arguments. Calls exit() if unhappy.
mDNSlocal void ParseCmdLinArgs(int argc, char **argv)
	{
	if (argc > 1)
		{
		if (0 == strcmp(argv[1], "-debug")) mDNS_DebugMode = mDNStrue;
		else printf("Usage: %s [-debug]\n", argv[0]);
		}

	if (!mDNS_DebugMode)
		{
		int result = daemon(0, 0);
		if (result != 0) { LogMsg("Could not run as daemon - exiting"); exit(result); }
#if __APPLE__
		LogMsg("The POSIX mdnsd should only be used on OS X for testing - exiting");
		exit(-1);
#endif
		}
	}

mDNSlocal void DumpStateLog(mDNS *const m)
// Dump a little log of what we've been up to.
	{
	LogMsg("---- BEGIN STATE LOG ----");
	udsserver_info(m);
	LogMsg("----  END STATE LOG  ----");
	}

mDNSlocal mStatus MainLoop(mDNS *m) // Loop until we quit.
	{
	sigset_t	signals;
	mDNSBool	gotData = mDNSfalse;

	mDNSPosixListenForSignalInEventLoop(SIGINT);
	mDNSPosixListenForSignalInEventLoop(SIGTERM);
	mDNSPosixListenForSignalInEventLoop(SIGUSR1);
	mDNSPosixListenForSignalInEventLoop(SIGPIPE);
	mDNSPosixListenForSignalInEventLoop(SIGHUP) ;

	for (; ;)
		{
		// Work out how long we expect to sleep before the next scheduled task
		struct timeval	timeout;
		mDNSs32			ticks;

		// Only idle if we didn't find any data the last time around
		if (!gotData)
			{
			mDNSs32			nextTimerEvent = mDNS_Execute(m);
			nextTimerEvent = udsserver_idle(nextTimerEvent);
			ticks = nextTimerEvent - mDNS_TimeNow(m);
			if (ticks < 1) ticks = 1;
			}
		else	// otherwise call EventLoop again with 0 timemout
			ticks = 0;

		timeout.tv_sec = ticks / mDNSPlatformOneSecond;
		timeout.tv_usec = (ticks % mDNSPlatformOneSecond) * 1000000 / mDNSPlatformOneSecond;

		(void) mDNSPosixRunEventLoopOnce(m, &timeout, &signals, &gotData);

		if (sigismember(&signals, SIGHUP )) Reconfigure(m);
		if (sigismember(&signals, SIGUSR1)) DumpStateLog(m);
		// SIGPIPE happens when we try to write to a dead client; death should be detected soon in request_callback() and cleaned up.
		if (sigismember(&signals, SIGPIPE)) LogMsg("Received SIGPIPE - ignoring");
		if (sigismember(&signals, SIGINT) || sigismember(&signals, SIGTERM)) break;
		}
	return EINTR;
	}

int main(int argc, char **argv)
	{
	mStatus					err;

	ParseCmdLinArgs(argc, argv);

	LogMsg("%s starting", mDNSResponderVersionString);

	err = mDNS_Init(&mDNSStorage, &PlatformStorage, gRRCache, RR_CACHE_SIZE, mDNS_Init_AdvertiseLocalAddresses, 
					mDNS_StatusCallback, mDNS_Init_NoInitCallbackContext); 

	if (mStatus_NoError == err)
		err = udsserver_init(mDNSNULL, 0);
		
	Reconfigure(&mDNSStorage);

	// Now that we're finished with anything privileged, switch over to running as "nobody"
	if (mStatus_NoError == err)
		{
		const struct passwd *pw = getpwnam("nobody");
		if (pw != NULL)
			setuid(pw->pw_uid);
		else
			LogMsg("WARNING: mdnsd continuing as root because user \"nobody\" does not exist");
		}

   if(mStatus_NoError != RegisterServicesInFile(SERVICES_FILE))
      LogMsg("Failed to register (some) services from %s.", SERVICES_FILE);

	if (mStatus_NoError == err)
		err = MainLoop(&mDNSStorage);
 
   DeregisterOurServices();
 
	LogMsg("%s stopping", mDNSResponderVersionString);

	mDNS_Close(&mDNSStorage);

	if (udsserver_exit() < 0)
		LogMsg("ExitCallback: udsserver_exit failed");
 
 #if MDNS_DEBUGMSGS > 0
	printf("mDNSResponder exiting normally with %ld\n", err);
 #endif
 
	return err;
	}

//		uds_daemon support		////////////////////////////////////////////////////////////

mStatus udsSupportAddFDToEventLoop(int fd, udsEventCallback callback, void *context, void **platform_data)
/* Support routine for uds_daemon.c */
	{
	// Depends on the fact that udsEventCallback == mDNSPosixEventCallback
	(void) platform_data;
	return mDNSPosixAddFDToEventLoop(fd, callback, context);
	}

int udsSupportReadFD(dnssd_sock_t fd, char *buf, int len, int flags, void *platform_data)
	{
	(void) platform_data;
	return recv(fd, buf, len, flags);
	}

mStatus udsSupportRemoveFDFromEventLoop(int fd, void *platform_data)		// Note: This also CLOSES the file descriptor
	{
	mStatus err = mDNSPosixRemoveFDFromEventLoop(fd);
	(void) platform_data;
	close(fd);
	return err;
	}

mDNSexport void RecordUpdatedNiceLabel(mDNS *const m, mDNSs32 delay)
	{
	(void)m;
	(void)delay;
	// No-op, for now
	}

// registering services from config file

#include <assert.h>

typedef struct PosixService PosixService;

struct PosixService {
    ServiceRecordSet coreServ;
    PosixService *next;
    int serviceID;
};

static PosixService *gServiceList = NULL;

static void RegistrationCallback(mDNS *const m, ServiceRecordSet *const thisRegistration, mStatus status)
    // mDNS core calls this routine to tell us about the status of 
    // our registration.  The appropriate action to take depends 
    // entirely on the value of status.
{
    switch (status) {

        case mStatus_NoError:      
            debugf("Callback: %##s Name Registered",   thisRegistration->RR_SRV.resrec.name->c); 
            // Do nothing; our name was successfully registered.  We may 
            // get more call backs in the future.
            break;

        case mStatus_NameConflict: 
            debugf("Callback: %##s Name Conflict",     thisRegistration->RR_SRV.resrec.name->c); 

            // In the event of a conflict, this sample RegistrationCallback 
            // just calls mDNS_RenameAndReregisterService to automatically 
            // pick a new unique name for the service. For a device such as a 
            // printer, this may be appropriate.  For a device with a user 
            // interface, and a screen, and a keyboard, the appropriate response 
            // may be to prompt the user and ask them to choose a new name for 
            // the service.
            //
            // Also, what do we do if mDNS_RenameAndReregisterService returns an 
            // error.  Right now I have no place to send that error to.

            status = mDNS_RenameAndReregisterService(m, thisRegistration, mDNSNULL);
            assert(status == mStatus_NoError);
            break;

        case mStatus_MemFree:      
            debugf("Callback: %##s Memory Free",       thisRegistration->RR_SRV.resrec.name->c); 

            // When debugging is enabled, make sure that thisRegistration 
            // is not on our gServiceList.

            #if !defined(NDEBUG)
                {
                    PosixService *cursor;

                    cursor = gServiceList;
                    while (cursor != NULL) {
                        assert(&cursor->coreServ != thisRegistration);
                        cursor = cursor->next;
                    }
                }
            #endif
            free(thisRegistration);
            break;

        default:                   
            debugf("Callback: %##s Unknown Status %ld", thisRegistration->RR_SRV.resrec.name->c, status); 
            break;
    }
}

static int gServiceID = 0;

static mDNSBool CheckThatRichTextNameIsUsable(const char *richTextName, mDNSBool printExplanation)
    // Checks that richTextName is reasonable 
    // label and, if it isn't and printExplanation is true, prints 
    // an explanation of why not.
{    
    mDNSBool result = mDNStrue;
    if (result && strlen(richTextName) > 63) {
        if (printExplanation) {
            LogMsg("%s: Service name is too long (must be 63 characters or less)\n", 
                    SERVICES_FILE);
        }
        result = mDNSfalse;
    }
    if (result && richTextName[0] == 0) {
        if (printExplanation) {
            LogMsg("%s: Service name can't be empty\n", SERVICES_FILE);
        }
        result = mDNSfalse;
    }
    return result;
}

static mDNSBool CheckThatServiceTypeIsUsable(const char *serviceType, mDNSBool printExplanation)
    // Checks that serviceType is a reasonable service type 
    // label and, if it isn't and printExplanation is true, prints 
    // an explanation of why not.
{
    mDNSBool result;

    result = mDNStrue;
    if (result && strlen(serviceType) > 63) {
        if (printExplanation) {
            LogMsg("%s: Service type is too long (must be 63 characters or less)\n", 
                    SERVICES_FILE);
        }
        result = mDNSfalse;
    }
    if (result && serviceType[0] == 0) {
        if (printExplanation) {
            LogMsg("%s: Service type can't be empty\n", 
                    SERVICES_FILE);
        }
        result = mDNSfalse;
    }
    return result;
}

static mDNSBool CheckThatPortNumberIsUsable(long portNumber, mDNSBool printExplanation)
    // Checks that portNumber is a reasonable port number
    // and, if it isn't and printExplanation is true, prints 
    // an explanation of why not.
{
    mDNSBool result;

    result = mDNStrue;
    if (result && (portNumber <= 0 || portNumber > 65535)) {
        if (printExplanation) {
               LogMsg("%s: Port number must be in range 1..65535\n", 
                    SERVICES_FILE);
        }
        result = mDNSfalse;
    }
    return result;
}

static mDNSBool ReadALine(char *buf, size_t bufSize, FILE *fp)
// Read a line, skipping over any blank lines or lines starting with '#'
{
	mDNSBool good, skip;
	do {
		good = (fgets(buf, bufSize, fp) != NULL);
		skip = (good && (buf[0] == '#'));
	} while (good && skip);
	if (good)
	{
		int		len = strlen( buf);
		if ( buf[len - 1] == '\r' || buf[len - 1] == '\n')
			buf[len - 1] = '\0';
	}
    return good;
}

static mStatus RegisterOneService(const char *  richTextName, 
                                  const char *  serviceType, 
                                  const char *  serviceDomain, 
                                  const mDNSu8  text[],
                                  mDNSu16       textLen,
                                  long          portNumber)
{
    mStatus             status;
    PosixService *      thisServ;
    domainlabel         name;
    domainname          type;
    domainname          domain;
    
    status = mStatus_NoError;
    thisServ = (PosixService *) malloc(sizeof(*thisServ));
    if (thisServ == NULL) {
        status = mStatus_NoMemoryErr;
    }
    if (status == mStatus_NoError) {
        MakeDomainLabelFromLiteralString(&name,  richTextName);
        MakeDomainNameFromDNSNameString(&type, serviceType);
        MakeDomainNameFromDNSNameString(&domain, serviceDomain);
        status = mDNS_RegisterService(&mDNSStorage, &thisServ->coreServ,
                &name, &type, &domain,				// Name, type, domain
                NULL, mDNSOpaque16fromIntVal(portNumber),
                text, textLen,						// TXT data, length
                NULL, 0,							// Subtypes
                mDNSInterface_Any,					// Interface ID
                RegistrationCallback, thisServ, // Callback and context
                0);                       //  flags
    }
    if (status == mStatus_NoError) {
        thisServ->serviceID = gServiceID;
        gServiceID += 1;

        thisServ->next = gServiceList;
        gServiceList = thisServ;

        if (gMDNSPlatformPosixVerboseLevel > 0) {
            LogMsg("%s: Registered service %d, name '%s', type '%s', port %ld\n", 
                    SERVICES_FILE, 
                    thisServ->serviceID, 
                    richTextName,
                    serviceType,
                    portNumber);
        }
    } else {
        if (thisServ != NULL) {
            free(thisServ);
        }
    }
    return status;
}

static const char kDefaultServiceDomain[] = "local.";

static mStatus RegisterServicesInFile(const char *filePath)
{
    mStatus     status = mStatus_NoError;
    FILE *      fp = fopen(filePath, "r");
    int         junk;

    if (fp == NULL) {
        status = mStatus_UnknownErr;
    }
    if (status == mStatus_NoError) {
        mDNSBool good = mDNStrue;
        do {
			int         ch;
			char name[256];
			char type[256];
			const char *dom = kDefaultServiceDomain;
			char rawText[1024];
			mDNSu8  text[sizeof(RDataBody)];
			unsigned int textLen = 0;
			char port[256];

            // Skip over any blank lines.
            do ch = fgetc(fp); while ( ch == '\n' || ch == '\r' );
            if (ch != EOF) good = (ungetc(ch, fp) == ch);

            // Read three lines, check them for validity, and register the service.
			good = ReadALine(name, sizeof(name), fp);               
			if (good) {
				good = ReadALine(type, sizeof(type), fp);
			}
			if (good) {
				char *p = type;
				while (*p && *p != ' ') p++;
				if (*p) {
					*p = 0;
					dom = p+1;
				}
			}
			if (good) {
				good = ReadALine(port, sizeof(port), fp);
			}
			if (good) {
				good =     CheckThatRichTextNameIsUsable(name, mDNSfalse)
						&& CheckThatServiceTypeIsUsable(type, mDNSfalse)
						&& CheckThatPortNumberIsUsable(atol(port), mDNSfalse);
			}
			if (good) {
				while (1) {
					int len;
					if (!ReadALine(rawText, sizeof(rawText), fp)) break;
					len = strlen(rawText);
					if (len <= 255)
						{
						unsigned int newlen = textLen + 1 + len;
						if (len == 0 || newlen >= sizeof(text)) break;
						text[textLen] = len;
						mDNSPlatformMemCopy(text + textLen + 1, rawText, len);
						textLen = newlen;
						}
					else
						LogMsg("%s: TXT attribute too long for name = %s, type = %s, port = %s\n", 
							SERVICES_FILE, name, type, port);
				}
			}
			if (good) {
				status = RegisterOneService(name, type, dom, text, textLen, atol(port));
				if (status != mStatus_NoError) {
					LogMsg("%s: Failed to register service, name = %s, type = %s, port = %s\n", 
							SERVICES_FILE, name, type, port);
					status = mStatus_NoError;       // keep reading
				}
			}
        } while (good && !feof(fp));

        if ( ! good ) {
            LogMsg("%s: Error reading service file %s\n", SERVICES_FILE, filePath);
        }
    }

    if (fp != NULL) {
        junk = fclose(fp);
        assert(junk == 0);
    }

    return status;
}

static void DeregisterOurServices(void)
{
    PosixService *thisServ;
    int thisServID;
    
    while (gServiceList != NULL) {
        thisServ = gServiceList;
        gServiceList = thisServ->next;

        thisServID = thisServ->serviceID;
        
        mDNS_DeregisterService(&mDNSStorage, &thisServ->coreServ);

        if (gMDNSPlatformPosixVerboseLevel > 0) {
            LogMsg("%s: Deregistered service %d\n",
                    SERVICES_FILE, 
                    thisServ->serviceID);
        }
    }
}

#if _BUILDING_XCODE_PROJECT_
// If the process crashes, then this string will be magically included in the automatically-generated crash log
const char *__crashreporter_info__ = mDNSResponderVersionString_SCCS + 5;
asm(".desc ___crashreporter_info__, 0x10");
#endif

// For convenience when using the "strings" command, this is the last thing in the file
#if mDNSResponderVersion > 1
mDNSexport const char mDNSResponderVersionString_SCCS[] = "@(#) mDNSResponder-" STRINGIFY(mDNSResponderVersion) " (" __DATE__ " " __TIME__ ")";
#elif MDNS_VERSIONSTR_NODTS
mDNSexport const char mDNSResponderVersionString_SCCS[] = "@(#) mDNSResponder (Engineering Build)";
#else
mDNSexport const char mDNSResponderVersionString_SCCS[] = "@(#) mDNSResponder (Engineering Build) (" __DATE__ " " __TIME__ ")";
#endif
