/*****************************************************************************************************
 * Software License Agreement (BSD License)
 * Author : lime csitech
 *
 * Copyright (c) 2020-2030, LimeCsitech
 * All rights reserved.
 *
*****************************************************************************************************/



#include "../../plugins.h"
GCC_DIAG_OFF("-Wdeprecated-declarations")
#include <gcrypt.h>
GCC_DIAG_ON("-Wdeprecated-declarations")

#define CHALLENGE_LEN	16

struct eap_md5_data
{
	enum
	{
		EAP_MD5_CONTINUE, EAP_MD5_SUCCESS, EAP_MD5_FAILURE
	} state;
	u8 * challenge;
};

int eap_md5_configure(char * configfile);
int eap_md5_init(struct eap_state_machine *smd);
int eap_md5_initPickUp(struct eap_state_machine *smd);
int eap_md5_buildReq(struct eap_state_machine *smd, u8 eap_md5,
		struct eap_packet * eapPacket);
boolean eap_md5_check(struct eap_state_machine *smd, struct eap_packet *eapRespData);
int eap_md5_process(struct eap_state_machine *smd, struct eap_packet *eapRespData);
boolean eap_md5_isDone(struct eap_state_machine *smd);
void eap_md5_free(void * data);

REGISTER_METHOD("eap_md5", "eap_md5_configure", "eap_md5_init", "eap_md5_initPickUp", "eap_md5_buildReq", NULL, "eap_md5_check", "eap_md5_process", "eap_md5_isDone", NULL, NULL, "eap_md5_free")
;

int eap_md5_configure(char * configfile)
{
	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

	return 0;
}

int eap_md5_init(struct eap_state_machine *smd)
{
	struct eap_md5_data *data = NULL;
	CHECK_MALLOC(data = malloc(sizeof(struct eap_md5_data)));
	memset(data, 0, sizeof(struct eap_md5_data));
	data->state = EAP_MD5_CONTINUE;
	data->challenge = NULL;
	smd->methodData = (struct eap_md5_data*) data;
	return 0;
}


int eap_md5_buildReq(struct eap_state_machine *smd, u8 id,
		struct eap_packet * eapPacket)
{
	struct eap_md5_data * data;
	u8 *payload, *challenge;

	data = (struct eap_md5_data *) smd->methodData;
	CHECK_MALLOC( challenge=malloc(sizeof(u8)*CHALLENGE_LEN));
	CHECK_MALLOC( payload=malloc(sizeof(u8)*(CHALLENGE_LEN+1)));
	memset(payload, 0, sizeof(u8) * (CHALLENGE_LEN + 1));

	gcry_create_nonce(challenge,CHALLENGE_LEN);
	U8COPY(payload, 1, CHALLENGE_LEN, challenge);
	payload[0] = (u8) CHALLENGE_LEN;
	CHECK_FCT(diameap_eap_new(EAP_REQUEST, id, TYPE_EAP_MD5, payload, CHALLENGE_LEN
					+ 1,eapPacket));
	CHECK_MALLOC(data->challenge=realloc(data->challenge,sizeof(u8)*CHALLENGE_LEN));
	U8COPY(data->challenge,0,CHALLENGE_LEN,challenge);

	smd->methodData = data;

	free(challenge);
	challenge=NULL;
	free(payload);
	payload=NULL;

	return 0;
}


boolean eap_md5_check(struct eap_state_machine *smd, struct eap_packet *eapRespData)
{
	eap_type type;
	if(diameap_eap_get_type(eapRespData,&type)!=0){
		return FALSE;
	}
	if (type == TYPE_EAP_MD5)
	{
		u16 length;
		CHECK_FCT(diameap_eap_get_length(eapRespData,&length));
		if ((int) length < 6)
		{
			TRACE_DEBUG(INFO,"%s[EAP MD5 plugin] Incorrect EAP packet received (length = %d ).",DIAMEAP_EXTENSION,length);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}



int eap_md5_process(struct eap_state_machine *smd, struct eap_packet *eapRespData)
{

	struct eap_md5_data * data;
	int wordlen = 0, i = 0;
	u8 * word, *hash, id;
	data = (struct eap_md5_data*) smd->methodData;
	wordlen = 1 + smd->user.passwordLength + CHALLENGE_LEN;
	CHECK_MALLOC(word = malloc(sizeof(u8)*wordlen));
	memset(word, 0, sizeof(u8) * wordlen);
	CHECK_FCT(diameap_eap_get_identifier(eapRespData,&id));
	*word = id;
	U8COPY(word,1,smd->user.passwordLength,smd->user.password);
	U8COPY(word,1+smd->user.passwordLength,CHALLENGE_LEN,data->challenge);
	CHECK_MALLOC(hash = malloc(sizeof(u8)*16));

	md5hash(word, wordlen, hash);


	for (i = 0; i < CHALLENGE_LEN; i++)
	{
		if (G8(hash + i) != G8(eapRespData->data + 6 + i))
		{
			data->state = EAP_MD5_FAILURE;
		}
	}

	if (data->state != EAP_MD5_FAILURE)
	{
		data->state = EAP_MD5_SUCCESS;
		smd->user.success = TRUE;
	}

	smd->methodData = data;
	free(hash);
	hash=NULL;
	free(word);
	word=NULL;
	return 0;
}

boolean eap_md5_isDone(struct eap_state_machine *smd)
{
	struct eap_md5_data *data;
	data = (struct eap_md5_data*) smd->methodData;
	if (data->state != EAP_MD5_CONTINUE)
	{
		return TRUE;
	}
	return FALSE;
}


void eap_md5_free(void * mdata)
{
	struct eap_md5_data *data;
	data = (struct eap_md5_data*) mdata;
	free(data->challenge);
	data->challenge=NULL;
	free(data);
	data=NULL;
}
