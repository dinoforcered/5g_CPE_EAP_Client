/*****************************************************************************************************
 * Software License Agreement (BSD License)
 * Author : lime csitech
 *
 * Copyright (c) 2020-2030, LimeCsitech
 * All rights reserved.
 *
*****************************************************************************************************/


#include "../../plugins.h"

struct identity_data
{
	enum
	{
		IDENTITY_CONTINUE, IDENTITY_SUCCESS, IDENTITY_FAILURE
	} state;
};

int identity_init(struct eap_state_machine *smd);
int identity_initPickUp(struct eap_state_machine *smd);
int identity_buildReq(struct eap_state_machine *smd, u8 identity, struct eap_packet * eapPacket);
boolean identity_check(struct eap_state_machine *smd, struct eap_packet *eapRespData);
int identity_process(struct eap_state_machine *smd, struct eap_packet *eapRespData);
boolean identity_isDone(struct eap_state_machine *smd);
void identity_free(void * data);

REGISTER_METHOD("identity", NULL, "identity_init", "identity_initPickUp", "identity_buildReq", NULL, "identity_check", "identity_process", "identity_isDone", NULL, NULL, "identity_free");


int identity_init(struct eap_state_machine *smd)
{
	struct identity_data *data = NULL;
	CHECK_MALLOC(data = malloc(sizeof(struct identity_data)));
	memset(data, 0, sizeof(struct identity_data));
	data->state = IDENTITY_CONTINUE;
	smd->methodData = (struct identity_data*) data;

	return 0;
}

int identity_initPickUp(struct eap_state_machine *smd)
{
	struct identity_data *data = NULL;
	CHECK_MALLOC(data = malloc(sizeof(struct identity_data)));
	memset(data, 0, sizeof(struct identity_data));
	data->state = IDENTITY_CONTINUE;
	smd->methodData = (struct identity_data*) data;
	return 0;
}

int identity_buildReq(struct eap_state_machine *smd, u8 identity, struct eap_packet * eapPacket)
{

	CHECK_FCT(diameap_eap_new(EAP_REQUEST, identity, TYPE_IDENTITY, NULL, 0,eapPacket));
	return 0;

}


boolean identity_check(struct eap_state_machine *smd, struct eap_packet *eapPacket)
{

	if (eapPacket->data == NULL)
	{
		TRACE_DEBUG(INFO,"%s[EAP Identity plugin] Empty EAP packet received.",DIAMEAP_EXTENSION);
		return FALSE;
	}
	eap_type type;
	if(diameap_eap_get_type(eapPacket,&type)!=0){
		return FALSE;
	}
	if (type == TYPE_IDENTITY)
	{
		u16 length;
		CHECK_FCT(diameap_eap_get_length(eapPacket,&length));
		if ((int)length < 6)
		{
			TRACE_DEBUG(INFO,"%s[EAP Identity plugin] Incorrect EAP packet received (length = %d ).",DIAMEAP_EXTENSION,length);
			return FALSE;
		}
		if ((int)length > 1020)
		{
			TRACE_DEBUG(INFO,"%s[EAP Identity plugin] Incorrect EAP packet received (length = %d ).",DIAMEAP_EXTENSION,length);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

int identity_process(struct eap_state_machine *smd, struct eap_packet *eapRespData)
{
	struct identity_data * data;
	u16 length;
	char * user;
	u8 * Respdata;
	int len,ret;

	CHECK_FCT(diameap_eap_get_length(eapRespData,&length));
	data = (struct identity_data*) smd->methodData;

	CHECK_MALLOC(user=malloc(sizeof(char)*((int)length-4)));

	diameap_eap_get_data(eapRespData,&Respdata,&len);
	if(Respdata==NULL){
		data->state = IDENTITY_FAILURE;
		goto end;
	}
	U8COPY((u8 *)user,0,len,Respdata);
	user[length-5]='\0';
	if(check_user_identity == FALSE){
		ret=diameap_get_eap_user(&(smd->user),"Default User");
		CHECK_MALLOC_DO(smd->user.userid=realloc(smd->user.userid,strlen(user)+1),{ret = 1; goto next;});
		memcpy(smd->user.userid,user,strlen(user)+1);
		smd->user.useridLength = strlen(user);
	} else {
		ret=diameap_get_eap_user(&(smd->user),user);
	}
next:
	if(ret==0)
	{
		smd->user.methodId = -1;
		data->state = IDENTITY_SUCCESS;
	}else{
		data->state = IDENTITY_FAILURE;
	}
end:
	smd->methodData = data;
	free(user);
	user=NULL;
	return 0;
}

boolean identity_isDone(struct eap_state_machine *smd)
{
	struct identity_data *data;
	data = (struct identity_data*) smd->methodData;
	if (data->state != IDENTITY_CONTINUE)
		return TRUE;
	else
		return FALSE;
}

void identity_free(void * data)
{
	free(data);
	data=NULL;
}
