/*****************************************************************************************************
 * Software License Agreement (BSD License)
 * Author : lime csitech
 *
 * Copyright (c) 2020-2030, LimeCsitech
 * All rights reserved.
 *
*****************************************************************************************************/



#ifndef DIAMEAP_EAP_H_
#define DIAMEAP_EAP_H_


/************************************************/
/*		EAP AAA Interface						*/
/************************************************/

/* EAP Backend Authenticator State Machine */
struct diameap_eap_interface
{

	/* Variables (AAA Interface to Backend Authenticator)*/
	boolean aaaEapResp;
	struct eap_packet aaaEapRespData;

	/*Variables (Backend Authenticator to AAA Interface )*/
	boolean aaaEapReq;
	boolean aaaEapNoReq;
	boolean aaaSuccess;
	boolean aaaFail;
	struct eap_packet aaaEapReqData;
	u8 *aaaEapMSKData;
	int aaaEapMSKLength;
	u8 *aaaEapEMSKData;
	int aaaEapEMSKLength;
	boolean aaaEapKeyAvailable;
	int aaaMethodTimeout;

};

int diameap_eap_statemachine(struct eap_state_machine * sm, struct diameap_eap_interface * eap_i, boolean * error);


#endif /* EAP_H_ */
