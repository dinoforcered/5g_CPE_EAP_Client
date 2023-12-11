/*****************************************************************************************************
 * Software License Agreement (BSD License)
 * Author : lime csitech
 *
 * Copyright (c) 2020-2030, LimeCsitech
 * All rights reserved.
 *
*****************************************************************************************************/


#ifndef DIAMEAP_H_
#define DIAMEAP_H_

/* Structure to hold configuration of DiamEAP*/
struct diameap_conf
{
	char *conffile; /* configuration file of the extension*/

	int authorize; /* Set to 1 if provides Authorization. Otherwise set to 0. (by default set to 0)*/

	u32 vendor_id; /* Vendor ID*/
	u32 application_id; /* Diameter EAP Application ID. Value set to 5. */
	u32 command_code; /* Diameter EAP Application Command Code. Value set to 268. */

	char * diam_realm; /* Diameter realm of the peer */

	/*Diameter EAP Server*/
	int max_invalid_eap_packet;

	//MySQL Database parameters

	struct {
		char *server;
		char *user;
		char *password;
		char *database;
	}db;

	u32 multi_round_time_out;
};

/* The pointer to access DiamEAP configuration*/
extern struct diameap_conf *diameap_config;

/* Initialize the configuration of DiamEAP*/
int diameap_init(char * conffile);

/* parser */
int diameapparse(struct diameap_conf * config);


#endif /* DIAMEAP_H_ */
