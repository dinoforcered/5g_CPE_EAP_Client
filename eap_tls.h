/*****************************************************************************************************
 * Software License Agreement (BSD License)
 * Author : lime csitech
 *
 * Copyright (c) 2020-2030, LimeCsitech
 * All rights reserved.
 *
*****************************************************************************************************/


#ifndef EAP_TLS_H_
#define EAP_TLS_H_

#include "../../plugins.h"

struct tls_config	tls_global_conf;

int diameap_eap_tls_buildReq_ack(u8 id, struct eap_packet * eapPacket);
int diameap_eap_tls_buildReq_start(u8 id, struct eap_packet * eapPacket);
int diameap_eap_tls_buildReq_data(struct tls_data * data,int id,struct eap_packet * eapPacket);
int diameap_eap_tls_parse(struct tls_msg * eaptls,struct eap_packet *eapPacket);
int eaptlsparse(struct tls_config * conf);

#endif /* EAP_TLS_H_ */
