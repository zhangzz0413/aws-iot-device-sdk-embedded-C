/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef SHADOW_DEMO_HELPERS_H_
#define SHADOW_DEMO_HELPERS_H_

/* Include Demo Config as the first non-system header. */
#include "demo_config.h"

/* MQTT API header. */
#include "core_mqtt.h"

/* corePKCS11 include. */
#include "core_pkcs11.h"

/**
 * @brief Establish a MQTT connection.
 *
 * @param[in] publishCallback The callback function to receive incoming
 * publishes from the MQTT broker.
 * @param[in] p11Session The PKCS #11 session to use.
 * @param[in] pClientCertLabel The client certificate PKCS #11 label to use.
 * @param[in] pPrivateKeyLabel The private key PKCS #11 label for the client certificate.
 *
 * @return true if an MQTT session is established;
 * false otherwise.
 */
int32_t EstablishMqttSession(MQTTEventCallback_t eventCallback,
                             CK_SESSION_HANDLE p11Session,
                             char * pClientCertLabel,
                             char * pPrivateKeyLabel );

/**
 * @brief Close the MQTT connection.
 *
 * @return EXIT_SUCCESS if DISCONNECT was successfully sent;
 * EXIT_FAILURE otherwise.
 */
int32_t DisconnectMqttSession( void );

/**
 * @brief Subscribe to a MQTT topic filter.
 *
 * @param[in] pTopicFilter Pointer to the shadow topic buffer.
 * @param[in] topicFilterLength Indicates the length of the shadow
 * topic buffer.
 *
 * @return EXIT_SUCCESS if SUBSCRIBE was successfully sent;
 * EXIT_FAILURE otherwise.
 */
int32_t SubscribeToTopic( const char * pTopicFilter,
                          uint16_t topicFilterLength );

/**
 * @brief Sends an MQTT UNSUBSCRIBE to unsubscribe from the shadow
 * topic.
 *
 * @param[in] pTopicFilter Pointer to the shadow topic buffer.
 * @param[in] topicFilterLength Indicates the length of the shadow
 * topic buffer.
 *
 * @return EXIT_SUCCESS if UNSUBSCRIBE was successfully sent;
 * EXIT_FAILURE otherwise.
 */
int32_t UnsubscribeFromTopic( const char * pTopicFilter,
                              uint16_t topicFilterLength );

/**
 * @brief Publish a message to a MQTT topic.
 *
 * @param[in] pTopicFilter Points to the topic.
 * @param[in] topicFilterLength The length of the topic.
 * @param[in] pPayload Points to the payload.
 * @param[in] payloadLength The length of the payload.
 *
 * @return EXIT_SUCCESS if PUBLISH was successfully sent;
 * EXIT_FAILURE otherwise.
 */
int32_t PublishToTopic( const char * pTopicFilter,
                        int32_t topicFilterLength,
                        const char * pPayload,
                        size_t payloadLength );

#endif /* ifndef SHADOW_DEMO_HELPERS_H_ */
