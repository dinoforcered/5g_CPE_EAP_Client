/*****************************************************************************************************
 * Software License Agreement (BSD License)
 * Author : lime csitech
 *
 * Copyright (c) 2020-2030, LimeCsitech
 * All rights reserved.
 *
*****************************************************************************************************/



#ifndef LIBDIAMEAP_H_
#define LIBDIAMEAP_H_

#include <freeDiameter/extension.h>

#define DIAMEAP_EXTENSION "[DiamEAP extension] "

#include "diameap_defs.h"
#include "diameap_eappacket.h"
#include "diameap_user.h"
#include "diameap_mysql.h"

#include <math.h>
#include <dlfcn.h>


/* authentication and authorization attributes  */

struct auth_attribute
{
	struct fd_list chain;
	char * attrib;
	char * op;
	char * value;
};

struct avp_attribute
{
	struct fd_list chain;
	char * attrib;
	union avp_value value;
	int tofree;
};


/************************************************/
/*		EAP Methods	plugins							*/
/************************************************/

/* The register functions of an EAP method */
struct register_plugin
{
	char * configure;
	char * init;
	char * initPickUp;
	char * buildReq;
	char * isDone;
	char * process;
	char * check;
	char * getTimeout;
	char * getKey;
	char * unregister;
	char * datafree;
};

struct eap_state_machine;
/* List of plugins to load ( only EAP methods declared in the configuration file will be loaded) */
struct plugin
{
	struct fd_list chain; /* link in the list */
	u32 vendor;	/* vendor*/
	const char *methodname; /* name of the EAP method*/
	eap_type methodtype; /* type number of the EAP method */
	char *pluginfile; /* plugin filename */
	char *conffile; /* optional configuration file name for the method */
	void *handler; /* object returned by dlopen() */
	int (*eap_method_configure)(char * configfile); /* (Optional) address of the eap_method_configure method */
	int (*eap_method_init)(struct eap_state_machine *smd); /* address of the eap_method_init method */
	int (*eap_method_initPickUp)(struct eap_state_machine *smd); /* address of the eap_method_initPickUp method */
	int (*eap_method_buildReq)(struct eap_state_machine *smd,
			u8 identifier,struct eap_packet * eapPacket); /* address of the eap_method_buildReq method */
	int (*eap_method_getTimeout)(struct eap_state_machine *smd, int * timeout); /* address of the eap_method_getTimeout method */
	boolean (*eap_method_check)(struct eap_state_machine *smd,
			struct eap_packet * eapRespData); /* address of the eap_method_check method */
	int (*eap_method_process)(struct eap_state_machine *smd,
			struct eap_packet * eapRespData); /* address of the eap_method_process method */
	boolean (*eap_method_isDone)(struct eap_state_machine *smd); /* address of the eap_method_isDone method */
	int (*eap_method_getKey)(struct eap_state_machine *smd, u8 ** msk,int *msklength, 
			u8 ** emsk,int *emsklength); /* address of the eap_method_getKey method */
	void (*eap_method_unregister)(void); /* (Optional) address of the eap_method_unregister method */
	void (*eap_method_free)(void *); /* (Optional) address of the eap_method_datafree method */

};


/************************************************/
/*		EAP State Machine						*/
/************************************************/

/* EAP Policy Decision */
typedef enum
{
	DECISION_FAILURE = 0, DECISION_SUCCESS = 1, DECISION_CONTINUE = 2
} decision;

typedef enum
{
	EAP_M_END, EAP_M_CONTINUE, EAP_M_PROPOSED
} eap_method_state;

/* EAP Backend Authenticator State Machine (RFC4137) */
/* Most of variables are described in the part 6 of the RFC 4137 */
/* */
struct eap_state_machine
{
	/*Local state Machine Variables*/

	/* Long-Term (Maintained between Packets) */
	eap_type currentMethod;
	u32 currentVendor;
	int currentId;
	int lastId;
	void * methodData;
	struct plugin *selectedMethod;
	u8 NAKproposedMethods[251];

	eap_method_state methodState;

	struct eap_user user;

	/* Short-Term (Not Maintained between exchanged Diameter EAP messages)*/
	boolean rxResp;
	int respId;
	eap_type respMethod;
	int respVendorMethod;
	u32 respVendor;
	decision sm_decision;
	enum
	{
		EAP_INITIALIZE,
		EAP_PICK_UP_METHOD,
		EAP_IDLE,
		EAP_RECEIVED,
		EAP_SEND_REQUEST,
		EAP_INTEGRITY_CHECK,
		EAP_METHOD_REQUEST,
		EAP_METHOD_RESPONSE,
		EAP_PROPOSE_METHOD,
		EAP_NAK,
		EAP_SELECT_ACTION,
		EAP_END,
		EAP_DISCARD
	} eap_state;

};



#endif /* LIBDIAMEAP_H_ */
