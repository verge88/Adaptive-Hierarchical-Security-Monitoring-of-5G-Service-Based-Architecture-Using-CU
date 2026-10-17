/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "nnrf-handler.h"
#include "sbi-path.h"

#include "sbi/openapi/external/cJSON.h"
#include <unistd.h>
#include <time.h>

/*
 * Stage 38 research-only multi-NF NRF discovery instrumentation.
 *
 * The registry itself is untouched. Only serialized discovery responses are
 * modified immediately before the stock Open5GS send path. The private plan
 * is local to the external testbed and is indexed independently per NF type.
 *
 * Plan format:
 *   <NF_TYPE> TAB <local discovery tick> TAB <kind> TAB <parameter>
 *
 * Parameter encoding:
 *   slot_code * 100 + variant, where slot_code identifies one of the thirteen
 *   discovery-visible Open5GS NF processes and variant is 1..4.
 */
#include <stdio.h>

#define STAGE38_ENABLE_PATH "/run/stage38/enabled"
#define STAGE38_PLAN_PATH "/run/stage38/plan.tsv"
#define STAGE39_KIE_EXTENSION_PATH "/run/stage39/kie-extension.json"
#define STAGE38_MAX_PLAN 8192
#define STAGE38_KIND_LEN 48
#define STAGE38_TYPE_LEN 16

typedef struct stage38_plan_entry_s {
    char target_type[STAGE38_TYPE_LEN];
    unsigned long tick;
    char kind[STAGE38_KIND_LEN];
    int parameter;
} stage38_plan_entry_t;

static stage38_plan_entry_t stage38_plan[STAGE38_MAX_PLAN];
static size_t stage38_plan_count = 0;
static bool stage38_plan_loaded = false;

static void stage38_load_plan_once(void)
{
    FILE *fp = NULL;
    char line[256];

    if (stage38_plan_loaded)
        return;

    stage38_plan_loaded = true;
    fp = fopen(STAGE38_PLAN_PATH, "r");
    if (!fp) {
        ogs_error("STAGE38: cannot open private plan [%s]", STAGE38_PLAN_PATH);
        return;
    }

    while (fgets(line, sizeof(line), fp) &&
            stage38_plan_count < STAGE38_MAX_PLAN) {
        char target_type[STAGE38_TYPE_LEN] = {0};
        unsigned long tick = 0;
        char kind[STAGE38_KIND_LEN] = {0};
        int parameter = 1;

        if (sscanf(line, "%15s\t%lu\t%47s\t%d",
                    target_type, &tick, kind, &parameter) != 4)
            continue;

        ogs_cpystrn(stage38_plan[stage38_plan_count].target_type,
                target_type,
                sizeof(stage38_plan[stage38_plan_count].target_type));
        stage38_plan[stage38_plan_count].tick = tick;
        ogs_cpystrn(stage38_plan[stage38_plan_count].kind,
                kind, sizeof(stage38_plan[stage38_plan_count].kind));
        stage38_plan[stage38_plan_count].parameter = parameter;
        stage38_plan_count++;
    }

    fclose(fp);
    ogs_info("STAGE38: loaded %zu private multi-NF mutation entries",
            stage38_plan_count);
}

static stage38_plan_entry_t *stage38_entry_for(
        const char *target_type, unsigned long tick)
{
    size_t i;

    stage38_load_plan_once();
    for (i = 0; i < stage38_plan_count; i++) {
        if (stage38_plan[i].tick == tick &&
                !strcmp(stage38_plan[i].target_type, target_type))
            return &stage38_plan[i];
    }
    return NULL;
}

static unsigned long *stage38_counter_for(const char *target_type)
{
    static unsigned long nssf = 0;
    static unsigned long ausf = 0;
    static unsigned long bsf = 0;
    static unsigned long udm = 0;
    static unsigned long amf = 0;
    static unsigned long smf = 0;
    static unsigned long pcf = 0;
    static unsigned long scp = 0;
    static unsigned long nrf = 0;

    if (!strcmp(target_type, "NSSF")) return &nssf;
    if (!strcmp(target_type, "AUSF")) return &ausf;
    if (!strcmp(target_type, "BSF")) return &bsf;
    if (!strcmp(target_type, "UDM")) return &udm;
    if (!strcmp(target_type, "AMF")) return &amf;
    if (!strcmp(target_type, "SMF")) return &smf;
    if (!strcmp(target_type, "PCF")) return &pcf;
    if (!strcmp(target_type, "SCP")) return &scp;
    if (!strcmp(target_type, "NRF")) return &nrf;
    return NULL;
}

static int stage38_slot_code(int parameter)
{
    int code = parameter / 100;
    return (code >= 1 && code <= 13) ? code : 1;
}

static int stage38_variant(int parameter)
{
    int variant = parameter % 100;
    return (variant >= 1 && variant <= 4) ? variant : 1;
}

static const char *stage38_endpoint_for_slot(int slot_code)
{
    switch (slot_code) {
    case 1: return "127.0.0.12";
    case 2: return "127.0.0.13";
    case 3: return "127.0.0.14";
    case 4: return "127.0.0.15";
    case 5: return "127.0.0.16";
    case 6: return "127.0.0.17";
    case 7: return "127.0.0.18";
    case 8: return "127.0.0.19";
    case 9: return "127.0.0.20";
    case 10: return "127.0.0.21";
    case 11: return "127.0.0.22";
    case 12: return "127.0.0.11";
    case 13: return "127.0.0.10";
    default: return "127.0.0.12";
    }
}

static cJSON *stage38_profile_by_slot(cJSON *instances, int slot_code)
{
    const char *endpoint = stage38_endpoint_for_slot(slot_code);
    int i, j;

    for (i = 0; i < cJSON_GetArraySize(instances); i++) {
        cJSON *profile = cJSON_GetArrayItem(instances, i);
        cJSON *addresses = profile ?
            cJSON_GetObjectItemCaseSensitive(profile, "ipv4Addresses") : NULL;

        if (!cJSON_IsArray(addresses))
            continue;

        for (j = 0; j < cJSON_GetArraySize(addresses); j++) {
            cJSON *address = cJSON_GetArrayItem(addresses, j);
            if (cJSON_IsString(address) &&
                    strcmp(address->valuestring, endpoint) == 0)
                return profile;
        }
    }
    return NULL;
}

static bool stage38_identity_replacement(
        cJSON *instances, unsigned long tick, int parameter)
{
    int slot = stage38_slot_code(parameter);
    int variant = stage38_variant(parameter);
    cJSON *profile = stage38_profile_by_slot(instances, slot);
    cJSON *nf_id = profile ?
        cJSON_GetObjectItemCaseSensitive(profile, "nfInstanceId") : NULL;
    char replacement[64];

    if (!cJSON_IsString(nf_id))
        return false;

    snprintf(replacement, sizeof(replacement),
            "380000%02d-%04lu-4%02d0-8000-%012lu",
            slot, tick % 10000, variant,
            (tick * 193UL + (unsigned long)slot * 1009UL +
             (unsigned long)variant * 9176UL) % 1000000000000UL);
    cJSON_SetValuestring(nf_id, replacement);
    return true;
}

static bool stage38_endpoint_substitution(
        cJSON *instances, unsigned long tick, int parameter)
{
    int slot = stage38_slot_code(parameter);
    int variant = stage38_variant(parameter);
    cJSON *profile = stage38_profile_by_slot(instances, slot);
    cJSON *array = NULL;
    char address[32];
    const char *prefix;

    if (!profile)
        return false;

    prefix = variant == 1 ? "203.0.113" :
             variant == 2 ? "198.51.100" :
             variant == 3 ? "192.0.2" : "198.18.0";
    snprintf(address, sizeof(address), "%s.%lu",
            prefix,
            ((tick + (unsigned long)slot * 19UL +
              (unsigned long)variant * 23UL) % 200UL) + 1UL);

    cJSON_DeleteItemFromObjectCaseSensitive(profile, "ipv4Addresses");
    array = cJSON_CreateArray();
    if (!array)
        return false;
    cJSON_AddItemToArray(array, cJSON_CreateString(address));
    cJSON_AddItemToObject(profile, "ipv4Addresses", array);
    return true;
}

static bool stage38_service_injection(
        cJSON *instances, unsigned long tick, int parameter)
{
    int slot = stage38_slot_code(parameter);
    int variant = stage38_variant(parameter);
    cJSON *profile = stage38_profile_by_slot(instances, slot);
    cJSON *services = NULL;
    cJSON *service = NULL;
    cJSON *versions = NULL;
    cJSON *version = NULL;
    cJSON *endpoints = NULL;
    cJSON *endpoint = NULL;
    char sid[80];
    char service_name[80];
    char full_version[32];

    if (!profile)
        return false;

    snprintf(sid, sizeof(sid),
            "stage38-shadow-s%d-v%d-t%lu", slot, variant, tick);
    snprintf(service_name, sizeof(service_name),
            "stage38-shadow-service-%d", variant);
    snprintf(full_version, sizeof(full_version),
            "38.%d.%lu-lab", variant, tick % 1000UL);

    services = cJSON_CreateArray();
    service = cJSON_CreateObject();
    versions = cJSON_CreateArray();
    version = cJSON_CreateObject();
    endpoints = cJSON_CreateArray();
    endpoint = cJSON_CreateObject();
    if (!services || !service || !versions || !version ||
            !endpoints || !endpoint) {
        if (services) cJSON_Delete(services);
        if (service) cJSON_Delete(service);
        if (versions) cJSON_Delete(versions);
        if (version) cJSON_Delete(version);
        if (endpoints) cJSON_Delete(endpoints);
        if (endpoint) cJSON_Delete(endpoint);
        return false;
    }

    cJSON_AddStringToObject(service, "serviceInstanceId", sid);
    cJSON_AddStringToObject(service, "serviceName", service_name);
    cJSON_AddStringToObject(service, "scheme",
            variant == 2 ? "https" : "http");
    cJSON_AddStringToObject(service, "nfServiceStatus",
            variant == 4 ? "SUSPENDED" : "REGISTERED");
    cJSON_AddStringToObject(version, "apiVersionInUri", "v1");
    cJSON_AddStringToObject(version, "apiFullVersion", full_version);
    cJSON_AddItemToArray(versions, version);
    cJSON_AddItemToObject(service, "versions", versions);
    cJSON_AddStringToObject(endpoint, "ipv4Address", "198.18.38.1");
    cJSON_AddStringToObject(endpoint, "transport", "TCP");
    cJSON_AddNumberToObject(endpoint, "port", 9380 + slot);
    cJSON_AddItemToArray(endpoints, endpoint);
    cJSON_AddItemToObject(service, "ipEndPoints", endpoints);
    cJSON_AddItemToArray(services, service);

    cJSON_DeleteItemFromObjectCaseSensitive(profile, "nfServices");
    cJSON_AddItemToObject(profile, "nfServices", services);
    return true;
}

static bool stage38_fqdn_substitution(
        cJSON *instances, unsigned long tick, int parameter)
{
    int slot = stage38_slot_code(parameter);
    int variant = stage38_variant(parameter);
    cJSON *profile = stage38_profile_by_slot(instances, slot);
    char fqdn[96];

    if (!profile)
        return false;

    snprintf(fqdn, sizeof(fqdn),
            "nf%d-v%d-t%lu.stage38.invalid", slot, variant, tick);
    cJSON_DeleteItemFromObjectCaseSensitive(profile, "fqdn");
    cJSON_AddStringToObject(profile, "fqdn", fqdn);
    return true;
}

static bool stage38_nf_type_substitution(
        cJSON *instances, unsigned long tick, int parameter)
{
    int slot = stage38_slot_code(parameter);
    int variant = stage38_variant(parameter);
    cJSON *profile = stage38_profile_by_slot(instances, slot);
    cJSON *type = profile ?
        cJSON_GetObjectItemCaseSensitive(profile, "nfType") : NULL;
    const char *types[] = {
        "NSSF", "AUSF", "BSF", "UDM",
        "AMF", "SMF", "PCF", "SCP", "NRF"
    };
    const char *replacement;
    int index = (variant - 1) % 9;

    (void)tick;
    if (!cJSON_IsString(type))
        return false;

    replacement = types[index];
    if (!strcmp(type->valuestring, replacement))
        replacement = types[(index + 1) % 9];
    cJSON_SetValuestring(type, replacement);
    return true;
}

static bool stage38_compound_identity_service(
        cJSON *instances, unsigned long tick, int parameter)
{
    if (!stage38_identity_replacement(instances, tick, parameter))
        return false;
    return stage38_service_injection(instances, tick, parameter);
}

static bool stage39_duplicate_profile(
        cJSON *instances, unsigned long tick, int parameter)
{
    int slot = stage38_slot_code(parameter);
    cJSON *profile = stage38_profile_by_slot(instances, slot);
    cJSON *duplicate = NULL;

    (void)tick;
    if (!profile)
        return false;

    duplicate = cJSON_Duplicate(profile, true);
    if (!duplicate)
        return false;
    cJSON_AddItemToArray(instances, duplicate);
    return true;
}

static cJSON *stage39_load_kie_extension(void)
{
    FILE *fp = NULL;
    char buffer[8192];
    size_t length = 0;

    fp = fopen(STAGE39_KIE_EXTENSION_PATH, "r");
    if (!fp)
        return NULL;
    length = fread(buffer, 1, sizeof(buffer)-1, fp);
    fclose(fp);
    if (!length || length >= sizeof(buffer)-1)
        return NULL;
    buffer[length] = '\0';
    return cJSON_Parse(buffer);
}

static bool stage38_lab_instrument_discovery_response(
        ogs_sbi_response_t *response, OpenAPI_nf_type_e target_nf_type)
{
    const char *target_type = OpenAPI_nf_type_ToString(target_nf_type);
    unsigned long *counter = NULL;
    cJSON *root = NULL;
    cJSON *instances = NULL;
    cJSON *kie_extension = NULL;
    stage38_plan_entry_t *entry = NULL;
    char *serialized = NULL;
    char *owned = NULL;
    unsigned long tick = 0;
    struct timespec stage39_mutation_ts;
    double stage39_mutation_ns = 0;
    bool changed = false;
    bool kie_added = false;
    bool mutation_enabled =
        access(STAGE38_ENABLE_PATH, F_OK) == 0;
    bool kie_enabled =
        access(STAGE39_KIE_EXTENSION_PATH, F_OK) == 0;

    if (!response ||
        response->status != OGS_SBI_HTTP_STATUS_OK ||
        !response->http.content || !response->http.content_length ||
        (!mutation_enabled && !kie_enabled))
        return false;

    root = cJSON_Parse(response->http.content);
    if (!root)
        return false;
    instances = cJSON_GetObjectItemCaseSensitive(root, "nfInstances");
    if (!cJSON_IsArray(instances)) {
        cJSON_Delete(root);
        return false;
    }

    if (kie_enabled) {
        kie_extension = stage39_load_kie_extension();
        if (kie_extension) {
            cJSON_DeleteItemFromObjectCaseSensitive(
                root, "x-stage39-kie");
            cJSON_AddItemToObject(
                root, "x-stage39-kie", kie_extension);
            kie_added = true;
        } else {
            ogs_error(
                "STAGE39: cannot parse KIE SBI extension [%s]",
                STAGE39_KIE_EXTENSION_PATH);
        }
    }

    if (mutation_enabled) {
        counter = stage38_counter_for(target_type);
        if (counter) {
            tick = (*counter)++;
            entry = stage38_entry_for(target_type, tick);
        }

        if (entry) {
            if (!strcmp(entry->kind, "identity_replacement")) {
                changed = stage38_identity_replacement(
                    instances, tick, entry->parameter);
            } else if (!strcmp(entry->kind, "endpoint_substitution")) {
                changed = stage38_endpoint_substitution(
                    instances, tick, entry->parameter);
            } else if (!strcmp(entry->kind, "service_injection")) {
                changed = stage38_service_injection(
                    instances, tick, entry->parameter);
            } else if (!strcmp(entry->kind, "fqdn_substitution")) {
                changed = stage38_fqdn_substitution(
                    instances, tick, entry->parameter);
            } else if (!strcmp(entry->kind, "nf_type_substitution")) {
                changed = stage38_nf_type_substitution(
                    instances, tick, entry->parameter);
            } else if (!strcmp(entry->kind, "compound_identity_service")) {
                changed = stage38_compound_identity_service(
                    instances, tick, entry->parameter);
            } else if (!strcmp(entry->kind, "duplicate_profile")) {
                changed = stage39_duplicate_profile(
                    instances, tick, entry->parameter);
            } else {
                ogs_error(
                    "STAGE39: unknown plan kind [%s]", entry->kind);
            }

            if (!changed) {
                ogs_error(
                    "STAGE39: planned mutation failed "
                    "[type:%s tick:%lu kind:%s parameter:%d]",
                    target_type, tick, entry->kind, entry->parameter);
                cJSON_Delete(root);
                return false;
            }

            if (clock_gettime(
                    CLOCK_MONOTONIC, &stage39_mutation_ts) != 0) {
                ogs_error("STAGE39: clock_gettime failed");
                cJSON_Delete(root);
                return false;
            }
            stage39_mutation_ns =
                (double)stage39_mutation_ts.tv_sec * 1000000000.0 +
                (double)stage39_mutation_ts.tv_nsec;
            cJSON_DeleteItemFromObjectCaseSensitive(
                root, "stage39MutationMonotonicNs");
            cJSON_AddNumberToObject(
                root,
                "stage39MutationMonotonicNs",
                stage39_mutation_ns);
        }
    }

    if (!changed && !kie_added) {
        cJSON_Delete(root);
        return false;
    }

    serialized = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!serialized)
        return false;

    owned = ogs_strdup(serialized);
    cJSON_free(serialized);
    ogs_assert(owned);
    ogs_free(response->http.content);
    response->http.content = owned;
    response->http.content_length = strlen(owned);

    if (changed) {
        ogs_warn(
            "STAGE39_NATIVE_NRF_MULTI_NF_MUTATION "
            "type=%s tick=%lu kind=%s parameter=%d",
            target_type, tick, entry->kind, entry->parameter);
    }
    if (kie_added) {
        ogs_info(
            "STAGE39_KIE_SBI_EXTENSION type=%s",
            target_type);
    }
    return true;
}

static int discover_handler(
        int status, ogs_sbi_response_t *response, void *data);
static void handle_nf_discover_search_result(
        OpenAPI_search_result_t *SearchResult);

/**
 * Handles NF registration in NRF. Validates the PLMN-ID against configured
 * serving PLMN-IDs and registers the NF instance if valid.
 *
 * @param nf_instance The NF instance being registered.
 * @param stream The SBI stream for communication.
 * @param recvmsg The received SBI message.
 * @return true if registration is successful; otherwise, false.
 */
bool nrf_nnrf_handle_nf_register(ogs_sbi_nf_instance_t *nf_instance,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int status;
    ogs_sbi_response_t *response = NULL;

    OpenAPI_nf_profile_t *NFProfile = NULL;

    OpenAPI_lnode_t *node = NULL;
    bool plmn_valid = false;
    int i;

    ogs_assert(nf_instance);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    NFProfile = recvmsg->NFProfile;
    if (!NFProfile) {
        ogs_error("No NFProfile");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No NFProfile", NULL, NULL));
        return false;
    }

    if (!NFProfile->nf_instance_id) {
        ogs_error("No NFProfile.NFInstanceId");
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No NFProfile.NFInstanceId", NULL, NULL));
        return false;
    }

    if (!NFProfile->nf_type) {
        ogs_error("No NFProfile.NFType");
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No NFProfile.NFType", NULL, NULL));
        return false;
    }

    if (!NFProfile->nf_status) {
        ogs_error("No NFProfile.NFStatus");
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No NFProfile.NFStatus", NULL, NULL));
        return false;
    }

    /* Validate the PLMN-ID against configured serving PLMN-IDs */
    if (NFProfile->plmn_list) {
        /* Set PLMN status to invalid */
        plmn_valid = false;

        if (ogs_local_conf()->num_of_serving_plmn_id > 0 && NFProfile->plmn_list) {
            OpenAPI_list_for_each(NFProfile->plmn_list, node) {
                OpenAPI_plmn_id_t *PlmnId = node->data;
                if (PlmnId == NULL) {
                    continue;
                }
                for (i = 0; i < ogs_local_conf()->num_of_serving_plmn_id; i++) {
                    if (ogs_sbi_compare_plmn_list(
                                &ogs_local_conf()->serving_plmn_id[i],
                                PlmnId) == true) {
                        plmn_valid = true;
                        break;
                    }
                }
                if (plmn_valid) {
                    break;
                }
            }
        }

        /* Reject the registration if PLMN-ID is invalid */
        if (!plmn_valid) {
            ogs_error("PLMN-ID in NFProfile is not allowed");
            ogs_assert(true == ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, recvmsg,
                "PLMN-ID not allowed", NULL, NULL));
            return false;
        }
    }

    ogs_nnrf_nfm_handle_nf_profile(nf_instance, NFProfile);

    ogs_sbi_client_associate(nf_instance);

    switch (nf_instance->nf_type) {
    case OpenAPI_nf_type_SEPP:
        ogs_sbi_self()->sepp_instance = nf_instance;
        break;
    case OpenAPI_nf_type_SCP:
        ogs_sbi_self()->scp_instance = nf_instance;
        break;
    default:
        break;
    }

    /*
     * TS29.510
     * Table 6.1.6.2.2-1: Definition of type NFProfile
     * If not provided, the PLMN of the NRF are assumed for the NF.
     */
    if (ogs_local_conf()->num_of_serving_plmn_id &&
            NFProfile->plmn_list == NULL) {
        /* NRF has PLMN and NF does NOT have PLMN,
         * so, copy NRF PLMN to NF PLMN */
        memcpy(nf_instance->plmn_id, ogs_local_conf()->serving_plmn_id,
                sizeof(nf_instance->plmn_id));
        nf_instance->num_of_plmn_id = ogs_local_conf()->num_of_serving_plmn_id;
    }

    if (OGS_FSM_CHECK(&nf_instance->sm, nrf_nf_state_will_register)) {
        recvmsg->http.location = recvmsg->h.uri;
        status = OGS_SBI_HTTP_STATUS_CREATED;
    } else if (OGS_FSM_CHECK(&nf_instance->sm, nrf_nf_state_registered)) {
        status = OGS_SBI_HTTP_STATUS_OK;
    } else
        ogs_assert_if_reached();

    /* NRF uses pre-configured heartbeat if NFs did not send it */
    if (NFProfile->is_heart_beat_timer == false)
        nf_instance->time.heartbeat_interval =
            ogs_local_conf()->time.nf_instance.heartbeat_interval;

    /*
     * TS29.510
     * Annex B (normative):NF Profile changes in NFRegister and NFUpdate
     * (NF Profile Complete Replacement) responses
     */
    if (NFProfile->is_nf_profile_changes_support_ind == true &&
        NFProfile->nf_profile_changes_support_ind == true) {

        OpenAPI_nf_profile_t NFProfileChanges;
        ogs_sbi_message_t sendmsg;

        OpenAPI_plmn_id_t *PlmnId = NULL;
        OpenAPI_lnode_t *node = NULL;

        memset(&NFProfileChanges, 0, sizeof(NFProfileChanges));
        NFProfileChanges.nf_instance_id = NFProfile->nf_instance_id;
        NFProfileChanges.nf_type = NFProfile->nf_type;
        NFProfileChanges.nf_status = NFProfile->nf_status;
        if (NFProfile->is_heart_beat_timer == false) {
            if (nf_instance->time.heartbeat_interval) {
                NFProfileChanges.is_heart_beat_timer = true;
                NFProfileChanges.heart_beat_timer =
                    nf_instance->time.heartbeat_interval;
            }
        }
        NFProfileChanges.is_nf_profile_changes_ind = true;
        NFProfileChanges.nf_profile_changes_ind = true;

        if (ogs_local_conf()->num_of_serving_plmn_id &&
                NFProfile->plmn_list == NULL) {
            OpenAPI_list_t *PlmnIdList = NULL;

            PlmnIdList = OpenAPI_list_create();
            ogs_assert(PlmnIdList);

            for (i = 0; i < ogs_local_conf()->num_of_serving_plmn_id; i++) {
                PlmnId = ogs_sbi_build_plmn_id(
                        &ogs_local_conf()->serving_plmn_id[i]);
                ogs_assert(PlmnId);
                OpenAPI_list_add(PlmnIdList, PlmnId);
            }

            if (PlmnIdList->count)
                NFProfileChanges.plmn_list = PlmnIdList;
            else
                OpenAPI_list_free(PlmnIdList);
        }

        memset(&sendmsg, 0, sizeof(sendmsg));
        sendmsg.http.location = recvmsg->http.location;
        sendmsg.NFProfile = &NFProfileChanges;

        response = ogs_sbi_build_response(&sendmsg, status);

        OpenAPI_list_for_each(NFProfileChanges.plmn_list, node) {
            PlmnId = node->data;
            if (PlmnId)
                ogs_sbi_free_plmn_id(PlmnId);
        }
        OpenAPI_list_free(NFProfileChanges.plmn_list);

    } else {

        if (NFProfile->is_heart_beat_timer == false) {
            if (nf_instance->time.heartbeat_interval) {
                NFProfile->is_heart_beat_timer = true;
                NFProfile->heart_beat_timer =
                    nf_instance->time.heartbeat_interval;
            }
        }

        response = ogs_sbi_build_response(recvmsg, status);

    }

    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return true;
}

bool nrf_nnrf_handle_nf_update(ogs_sbi_nf_instance_t *nf_instance,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_response_t *response = NULL;
    OpenAPI_list_t *PatchItemList = NULL;
    OpenAPI_lnode_t *node;

    ogs_assert(nf_instance);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    cJSON *plmn_array = NULL, *plmn_item = NULL;
    bool plmn_valid = false;
    int i;

    SWITCH(recvmsg->h.method)
    CASE(OGS_SBI_HTTP_METHOD_PUT)
        return nrf_nnrf_handle_nf_register(
                nf_instance, stream, recvmsg);

    CASE(OGS_SBI_HTTP_METHOD_PATCH)
        PatchItemList = recvmsg->PatchItemList;
        if (!PatchItemList) {
            ogs_error("No PatchItemList Array");
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PatchItemList", NULL, NULL));
            return false;
        }

        /* Iterate through the PatchItemList */
        OpenAPI_list_for_each(PatchItemList, node) {
            OpenAPI_patch_item_t *patch_item = node->data;
            if (!patch_item) {
                ogs_error("No PatchItem");
                ogs_assert(true == ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, recvmsg,
                    "No PatchItem", NULL, NULL));
                return false;
            }

            if (patch_item->op != OpenAPI_patch_operation_replace) {
                ogs_error("Unknown PatchItem.Operation [%s]",
                        OpenAPI_patch_operation_ToString(patch_item->op));
                continue;
            }

            SWITCH(patch_item->path)
            CASE(OGS_SBI_PATCH_PATH_NF_STATUS)
                break;
            CASE(OGS_SBI_PATCH_PATH_LOAD)
                break;
            CASE(OGS_SBI_PATCH_PATH_PLMN_LIST)
                /* Ensure the value is not null and is a valid JSON array */
                if (patch_item->value && patch_item->value->json) {
                    /* Set PLMN status to invalid */
                    plmn_valid = false;

                    plmn_array = patch_item->value->json;
                    if (!cJSON_IsArray(plmn_array)) {
                        ogs_error("Value for /plmnList is not a JSON array");
                        ogs_assert(true == ogs_sbi_server_send_error(
                            stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, recvmsg,
                            "Invalid value for /plmnList", NULL, NULL));
                        return false;
                    }

                    /* Clear existing PLMN data in nf_instance */
                    memset(nf_instance->plmn_id, 0,
                            sizeof(nf_instance->plmn_id));
                    nf_instance->num_of_plmn_id = 0;

                    /* Iterate through the JSON array of PLMN IDs */
                    cJSON_ArrayForEach(plmn_item, plmn_array) {
                        OpenAPI_plmn_id_t plmn_id;
                        memset(&plmn_id, 0, sizeof(plmn_id));

                        if (nf_instance->num_of_plmn_id >=
                                OGS_ARRAY_SIZE(nf_instance->plmn_id)) {
                            ogs_error("Exceeded maximum number of PLMN IDs");
                            ogs_assert(true == ogs_sbi_server_send_error(
                                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                                recvmsg,
                                "Too many PLMN IDs", NULL, NULL));
                            return false;
                        }

                        /* Parse the PLMN item */
                        plmn_id.mcc = cJSON_GetObjectItem(plmn_item, "mcc")
                                           ? cJSON_GetStringValue(
                                                 cJSON_GetObjectItem(
                                                     plmn_item, "mcc"))
                                           : NULL;
                        plmn_id.mnc = cJSON_GetObjectItem(plmn_item, "mnc")
                                           ? cJSON_GetStringValue(
                                                 cJSON_GetObjectItem(
                                                     plmn_item, "mnc"))
                                           : NULL;

                        if (!plmn_id.mcc || !plmn_id.mnc) {
                            ogs_error(
                                "Invalid PLMN item in /plmnList update");
                            ogs_assert(true ==
                                       ogs_sbi_server_send_error(
                                           stream,
                                           OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                                           recvmsg,
                                           "Invalid PLMN item", NULL,
                                           NULL));
                            return false;
                        }

                        /*
                         * Convert OpenAPI_plmn_id_t to ogs_plmn_id_t
                         * and store in nf_instance
                         */
                        ogs_sbi_parse_plmn_id(
                                &nf_instance->
                                    plmn_id[nf_instance->num_of_plmn_id],
                                &plmn_id);
                        nf_instance->num_of_plmn_id++;

                        /* Compare with the serving PLMN list */
                        for (i = 0;
                             i < ogs_local_conf()->num_of_serving_plmn_id;
                             i++) {
                            if (ogs_sbi_compare_plmn_list(
                                        &ogs_local_conf()->serving_plmn_id[i],
                                        &plmn_id) == true) {
                                plmn_valid = true;
                                break;
                            }
                        }
                        if (plmn_valid) {
                            break;
                        }
                    }

                    /* Reject the update if PLMN-ID is invalid */
                    if (!plmn_valid) {
                        ogs_error("PLMN-ID in NFProfile update is not allowed");
                        ogs_assert(true == ogs_sbi_server_send_error(
                            stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST, recvmsg,
                            "PLMN-ID not allowed", NULL, NULL));
                        return false;
                    }
                }
                break;
            DEFAULT
                ogs_error("Unknown PatchItem.Path [%s]", patch_item->path);
            END
        }

        response = ogs_sbi_build_response(
                recvmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
        break;

    DEFAULT
        ogs_error("[%s] Invalid HTTP method [%s]",
                nf_instance->id, recvmsg->h.method);
        ogs_assert_if_reached();
    END

    return true;
}

bool nrf_nnrf_handle_nf_status_subscribe(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    bool rc;
    int status;
    ogs_sbi_response_t *response = NULL;
    OpenAPI_subscription_data_t *SubscriptionData = NULL;
    OpenAPI_subscr_cond_t *SubscrCond = NULL;
    ogs_sbi_subscription_data_t *subscription_data = NULL;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_header_t header;

    ogs_uuid_t uuid;
    char id[OGS_UUID_FORMATTED_LENGTH + 1];

    ogs_assert(stream);
    ogs_assert(recvmsg);

    if (recvmsg->h.resource.component[1]) {
        ogs_error("Invalid POST Format [%s]",
                recvmsg->h.resource.component[1]);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "Invalid POST Format",
                recvmsg->h.resource.component[1], NULL));
        return false;
    }

    SubscriptionData = recvmsg->SubscriptionData;
    if (!SubscriptionData) {
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No SubscriptionData", NULL, NULL));
        return false;
    }

    if (!SubscriptionData->nf_status_notification_uri) {
        ogs_error("No nfStatusNotificationUri");
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No SubscriptionData", "NFStatusNotificationURL",
                NULL));
        return false;
    }

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    subscription_data = ogs_sbi_subscription_data_add();
    ogs_assert(subscription_data);

    ogs_sbi_subscription_data_set_id(subscription_data, id);
    ogs_assert(subscription_data->id);

    subscription_data->req_nf_type = SubscriptionData->req_nf_type;
    if (SubscriptionData->req_nf_instance_id) {
        subscription_data->req_nf_instance_id =
            ogs_strdup(SubscriptionData->req_nf_instance_id);
        if (!subscription_data->req_nf_instance_id) {
            ogs_error("ogs_strdup() failed");
            ogs_sbi_subscription_data_remove(subscription_data);
            return false;
        }
    }

    if (SubscriptionData->subscription_id) {
        ogs_warn("[%s] NF should not send SubscriptionID",
                SubscriptionData->subscription_id);
        ogs_free(SubscriptionData->subscription_id);
    }
    SubscriptionData->subscription_id = ogs_strdup(subscription_data->id);
    if (!SubscriptionData->subscription_id) {
        ogs_error("ogs_strdup() failed");
        ogs_sbi_subscription_data_remove(subscription_data);
        return false;
    }

    if (SubscriptionData->requester_features) {
        subscription_data->requester_features =
            ogs_uint64_from_string_hexadecimal(
                    SubscriptionData->requester_features);

        /* No need to send SubscriptionData->requester_features to the NF */
        ogs_free(SubscriptionData->requester_features);
        SubscriptionData->requester_features = NULL;
    } else {
        subscription_data->requester_features = 0;
    }

    OGS_SBI_FEATURES_SET(subscription_data->nrf_supported_features,
            OGS_SBI_NNRF_NFM_SERVICE_MAP);
    SubscriptionData->nrf_supported_features =
        ogs_uint64_to_string(subscription_data->nrf_supported_features);
    if (!SubscriptionData->nrf_supported_features) {
        ogs_error("ogs_strdup() failed");
        ogs_sbi_subscription_data_remove(subscription_data);
        return false;
    }

    SubscrCond = SubscriptionData->subscr_cond;
    if (SubscrCond) {

    /* Issue #2630 : The format of subscrCond is invalid. Must be 'oneOf'. */
        if (SubscrCond->nf_type && SubscrCond->service_name) {
            ogs_error("SubscrCond must be 'oneOf'");
            ogs_sbi_subscription_data_remove(subscription_data);
            return false;
        }

        if (SubscrCond->nf_type)
            subscription_data->subscr_cond.nf_type = SubscrCond->nf_type;
        else if (SubscrCond->service_name)
            subscription_data->subscr_cond.service_name =
                ogs_strdup(SubscrCond->service_name);
        else if (SubscrCond->nf_instance_id)
            subscription_data->subscr_cond.nf_instance_id = 
                ogs_strdup(SubscrCond->nf_instance_id);
        else {
            ogs_error("No SubscrCond");
            ogs_sbi_subscription_data_remove(subscription_data);
            return false;
        }
    }

    subscription_data->notification_uri =
            ogs_strdup(SubscriptionData->nf_status_notification_uri);
    ogs_assert(subscription_data->notification_uri);

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            subscription_data->notification_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "Invalid URI", subscription_data->notification_uri,
                NULL));
        ogs_sbi_subscription_data_remove(subscription_data);
        return false;
    }

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        ogs_assert(client);
    }
    OGS_SBI_SETUP_CLIENT(subscription_data, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    /*
     * The NRF validity is initially set in configuration.
     */
    subscription_data->validity_duration =
        ogs_time_from_sec(
                ogs_local_conf()->time.subscription.validity_duration);

    if (subscription_data->validity_duration) {
        SubscriptionData->validity_time = ogs_sbi_localtime_string(
            ogs_time_now() + subscription_data->validity_duration);
        ogs_assert(SubscriptionData->validity_time);

        if (!subscription_data->t_validity) {
            subscription_data->t_validity =
                ogs_timer_add(ogs_app()->timer_mgr,
                    nrf_timer_subscription_validity, subscription_data);
            ogs_assert(subscription_data->t_validity);
        }
        ogs_timer_start(subscription_data->t_validity,
                subscription_data->validity_duration);
    }

    ogs_info("[%s] Subscription created until %s "
            "[duration:%lld,validity:%d.%06d]",
            subscription_data->id,
            SubscriptionData->validity_time,
            (long long)subscription_data->validity_duration,
            (int)ogs_time_sec(subscription_data->validity_duration),
            (int)ogs_time_usec(subscription_data->validity_duration));

    /* Location */
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NNRF_NFM;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
        (char *)OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS;
    header.resource.component[1] = subscription_data->id;

    recvmsg->http.location = ogs_sbi_server_uri(server, &header);

    status = OGS_SBI_HTTP_STATUS_CREATED;

    response = ogs_sbi_build_response(recvmsg, status);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    if (recvmsg->http.location)
        ogs_free(recvmsg->http.location);

    return true;
}

bool nrf_nnrf_handle_nf_status_update(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_response_t *response = NULL;

    OpenAPI_list_t *PatchItemList = NULL;
    OpenAPI_lnode_t *node;

    ogs_sbi_message_t sendmsg;
    OpenAPI_subscription_data_t SubscriptionData;
    char *validity_time = NULL;

    ogs_sbi_subscription_data_t *subscription_data = NULL;

    ogs_time_t time, validity;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    memset(&SubscriptionData, 0, sizeof(SubscriptionData));

    if (!recvmsg->h.resource.component[1]) {
        ogs_error("No SubscriptionId");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No SubscriptionId", NULL, NULL));
        return false;
    }

    subscription_data = ogs_sbi_subscription_data_find(
            recvmsg->h.resource.component[1]);
    if (!subscription_data) {
        ogs_error("[%s] Not found", recvmsg->h.resource.component[1]);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND,
                recvmsg, "Not found", recvmsg->h.resource.component[1],
                NULL));
        return false;
    }
    ogs_assert(subscription_data->id);

    PatchItemList = recvmsg->PatchItemList;
    if (!PatchItemList) {
        ogs_error("[%s] No PatchItemList Array", subscription_data->id);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No PatchItemList", subscription_data->id,
                NULL));
        return false;
    }

    OpenAPI_list_for_each(PatchItemList, node) {
        OpenAPI_patch_item_t *patch_item = node->data;
        if (!patch_item) {
            ogs_error("No PatchItem");
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PatchItem", NULL, NULL));
            return false;
        }

        if (patch_item->op != OpenAPI_patch_operation_replace) {
            ogs_error("Unknown PatchItem.Operation [%s]",
                    OpenAPI_patch_operation_ToString(patch_item->op));
            continue;
        }

        SWITCH(patch_item->path)
        CASE(OGS_SBI_PATCH_PATH_VALIDITY_TIME)
            if (patch_item->value && patch_item->value->json)
                validity_time =
                    cJSON_GetStringValue(patch_item->value->json);
            break;
        DEFAULT
            ogs_error("Unknown PatchItem.Path [%s]", patch_item->path);
        END
    }

    if (!validity_time) {
        ogs_error("[%s] No validityTime", subscription_data->id);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No validityTime", subscription_data->id,
                NULL));
        return false;
    }

    if (ogs_sbi_time_from_string(&time, validity_time) == false) {
        ogs_error("[%s] Subscription updated until %s [parser error]",
                subscription_data->id, validity_time);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "parse error", subscription_data->id,
                validity_time));
        return false;
    }

    validity = time - ogs_time_now();
    if (validity < 0) {
        ogs_error("[%s] Subscription updated until %s [validity:%d.%06d]",
                subscription_data->id, validity_time,
                (int)ogs_time_sec(validity), (int)ogs_time_usec(validity));
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "invalid validity", subscription_data->id,
                validity_time));
        return false;
    }

    /*
     * The NRF validity is updated if NF sent the PATCH Request.
     */
    subscription_data->validity_duration =
        /* Normalize seconds */
        ogs_time_from_sec(ogs_time_to_sec(validity));

    if (!subscription_data->t_validity) {
        subscription_data->t_validity =
            ogs_timer_add(ogs_app()->timer_mgr,
                nrf_timer_subscription_validity, subscription_data);
        ogs_assert(subscription_data->t_validity);
    }
    ogs_timer_start(subscription_data->t_validity,
            subscription_data->validity_duration);

    ogs_info("[%s] Subscription updated until %s "
            "[duration:%lld,validity:%d.%06d]",
            subscription_data->id, validity_time,
            (long long)subscription_data->validity_duration,
            (int)ogs_time_sec(subscription_data->validity_duration),
            (int)ogs_time_usec(subscription_data->validity_duration));

    /* To send SubscriptionData to the NF */
    memset(&sendmsg, 0, sizeof(sendmsg));

#if 0 /* Use HTTP_STATUS_NO_CONTENT(204) instead of HTTP_STATUS_OK(200) */
    sendmsg.SubscriptionData = &SubscriptionData;

    /* Mandatory */
    SubscriptionData.nf_status_notification_uri =
        subscription_data->notification_uri;

    /* Validity Time */
    SubscriptionData.validity_time = ogs_sbi_localtime_string(
        ogs_time_now() + subscription_data->validity_duration);
    ogs_assert(SubscriptionData.validity_time);

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
#else
    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
#endif
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    ogs_free(SubscriptionData.validity_time);

    return true;
}

bool nrf_nnrf_handle_nf_status_unsubscribe(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_subscription_data_t *subscription_data = NULL;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    if (!recvmsg->h.resource.component[1]) {
        ogs_error("No SubscriptionId");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No SubscriptionId", NULL, NULL));
        return false;
    }

    subscription_data = ogs_sbi_subscription_data_find(
            recvmsg->h.resource.component[1]);
    if (!subscription_data) {
        ogs_error("[%s] Not found", recvmsg->h.resource.component[1]);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND,
                recvmsg, "Not found", recvmsg->h.resource.component[1],
                NULL));
        return false;
    }

    ogs_assert(subscription_data->id);
    ogs_sbi_subscription_data_remove(subscription_data);

    response = ogs_sbi_build_response(
            recvmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return true;
}

bool nrf_nnrf_handle_nf_list_retrieval(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_server_t *server = NULL;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    int i = 0;

    ogs_sbi_links_t *links = NULL;
    OpenAPI_lnode_t *node = NULL;

    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(recvmsg);

    links = ogs_calloc(1, sizeof(*links));
    ogs_assert(links);

    links->items = OpenAPI_list_create();
    ogs_assert(links->items);

    links->self = ogs_sbi_server_uri(server, &recvmsg->h);

    i = 0;
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
        if (NF_INSTANCE_EXCLUDED_FROM_DISCOVERY(nf_instance))
            continue;

        if (recvmsg->param.nf_type &&
            recvmsg->param.nf_type != nf_instance->nf_type)
            continue;

        if (!recvmsg->param.limit ||
             (recvmsg->param.limit && i < recvmsg->param.limit)) {
            char *str = ogs_msprintf("%s/%s", links->self, nf_instance->id);
            ogs_assert(str);
            OpenAPI_list_add(links->items, str);
        }

        i++;
    }

    ogs_assert(links->self);

    memset(&sendmsg, 0, sizeof(sendmsg));
    sendmsg.links = links;
    sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    OpenAPI_list_for_each(links->items, node) {
        if (!node->data) continue;
        ogs_free(node->data);
    }
    OpenAPI_list_free(links->items);
    ogs_free(links->self);
    ogs_free(links);

    return true;
}

bool nrf_nnrf_handle_nf_profile_retrieval(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    ogs_assert(recvmsg->h.resource.component[1]);
    nf_instance = ogs_sbi_nf_instance_find(recvmsg->h.resource.component[1]);
    if (!nf_instance) {
        ogs_error("Not found [%s]", recvmsg->h.resource.component[1]);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND,
                recvmsg, "Not found", recvmsg->h.resource.component[1],
                NULL));
        return false;
    }

    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.NFProfile = ogs_nnrf_nfm_build_nf_profile(
            nf_instance, NULL, NULL, true);
    if (!sendmsg.NFProfile) {
        ogs_error("ogs_nnrf_nfm_build_nf_profile() failed");
        return false;
    }

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    ogs_nnrf_nfm_free_nf_profile(sendmsg.NFProfile);

    return true;
}

bool nrf_nnrf_handle_nf_discover(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_discovery_option_t *discovery_option = NULL;

    OpenAPI_search_result_t *SearchResult = NULL;
    OpenAPI_nf_profile_t *NFProfile = NULL;
    OpenAPI_lnode_t *node = NULL;
    int i;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    if (!recvmsg->param.target_nf_type) {
        ogs_error("No target-nf-type [%s]", recvmsg->h.uri);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No target-nf-type", NULL, NULL));
        return false;
    }
    if (!recvmsg->param.requester_nf_type) {
        ogs_error("No requester-nf-type [%s]", recvmsg->h.uri);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No requester-nf-type", NULL, NULL));
        return false;
    }

    ogs_debug("NF-Discover : Requester[%s] Target[%s]",
            OpenAPI_nf_type_ToString(recvmsg->param.requester_nf_type),
            OpenAPI_nf_type_ToString(recvmsg->param.target_nf_type));

    if (recvmsg->param.discovery_option)
        discovery_option = recvmsg->param.discovery_option;

    if (discovery_option) {
        if (discovery_option->target_nf_instance_id) {
            ogs_debug("target-nf-instance-id[%s]",
                discovery_option->target_nf_instance_id);
        }
        if (discovery_option->requester_nf_instance_id) {
            ogs_debug("requester-nf-instance-id[%s]",
                discovery_option->requester_nf_instance_id);
        }
        if (discovery_option->num_of_service_names) {
            for (i = 0; i < discovery_option->num_of_service_names; i++)
                ogs_debug("[%d] service-names[%s]", i,
                    discovery_option->service_names[i]);
        }
        if (discovery_option->num_of_snssais) {
            for (i = 0; i < discovery_option->num_of_snssais; i++)
                ogs_debug("[%d] snssais[SST:%d SD:0x%x]", i,
                        discovery_option->snssais[i].sst,
                        discovery_option->snssais[i].sd.v);
        }
        if (discovery_option->dnn) {
            ogs_debug("dnn[%s]", discovery_option->dnn);
        }
        if (discovery_option->tai_presence) {
            ogs_debug("tai[PLMN_ID:%06x,TAC:%d]",
                        ogs_plmn_id_hexdump(
                            &discovery_option->tai.plmn_id),
                        discovery_option->tai.tac.v);
        }
        if (discovery_option->guami_presence) {
            ogs_debug("guami[PLMN_ID:%06x,UDM_ID:%x]",
                        ogs_plmn_id_hexdump(
                            &discovery_option->guami.plmn_id),
                        ogs_amf_id_hexdump(
                            &discovery_option->guami.amf_id));
        }
        if (discovery_option->num_of_target_plmn_list) {
            for (i = 0; i < discovery_option->num_of_target_plmn_list; i++)
                ogs_debug("[%d] target-plmn-list[MCC:%03d,MNC:%03d]", i,
                    ogs_plmn_id_mcc(
                        &discovery_option->target_plmn_list[i]),
                    ogs_plmn_id_mnc(
                        &discovery_option->target_plmn_list[i]));
        }
        if (discovery_option->num_of_requester_plmn_list) {
            for (i = 0; i < discovery_option->num_of_requester_plmn_list; i++)
                ogs_debug("[%d] requester-plmn-list[MCC:%03d,MNC:%03d]", i,
                    ogs_plmn_id_mcc(
                        &discovery_option->requester_plmn_list[i]),
                    ogs_plmn_id_mnc(
                        &discovery_option->requester_plmn_list[i]));
        }
        if (discovery_option->requester_features) {
            ogs_debug("requester-features[0x%llx]",
                (long long)discovery_option->requester_features);
        }
    }

    SearchResult = ogs_calloc(1, sizeof(*SearchResult));
    ogs_assert(SearchResult);

    SearchResult->nf_instances = OpenAPI_list_create();
    ogs_assert(SearchResult->nf_instances);

    i = 0;
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
        if (NF_INSTANCE_EXCLUDED_FROM_DISCOVERY(nf_instance))
            continue;

        if (nf_instance->nf_type != recvmsg->param.target_nf_type)
            continue;

        if (ogs_sbi_nf_instance_is_allowed_nf_type(
                nf_instance, recvmsg->param.requester_nf_type) == false)
            continue;

        if (discovery_option &&
            ogs_sbi_discovery_option_is_matched(
                nf_instance,
                recvmsg->param.requester_nf_type,
                discovery_option) == false)
            continue;

        if (recvmsg->param.limit && i >= recvmsg->param.limit)
            break;

        ogs_debug("[%s:%d] NF-Discovered [NF-Type:%s,NF-Status:%s,"
                "IPv4:%d,IPv6:%d]", nf_instance->id, i,
                OpenAPI_nf_type_ToString(nf_instance->nf_type),
                OpenAPI_nf_status_ToString(nf_instance->nf_status),
                nf_instance->num_of_ipv4, nf_instance->num_of_ipv6);

        NFProfile = ogs_nnrf_nfm_build_nf_profile(
                nf_instance, NULL, discovery_option,
                discovery_option &&
                OGS_SBI_FEATURES_IS_SET(
                    discovery_option->requester_features,
                    OGS_SBI_NNRF_DISC_SERVICE_MAP) ? true : false);

        if (!NFProfile) {
            ogs_error("No NFProfile");
            continue;
        }

        OpenAPI_list_add(SearchResult->nf_instances, NFProfile);

        i++;
    }

    if (recvmsg->param.limit) SearchResult->num_nf_inst_complete = i;

    memset(&sendmsg, 0, sizeof(sendmsg));

    if (SearchResult->nf_instances->count) {

        /* NF-Instances are Discovered */

        SearchResult->is_validity_period = true;
        SearchResult->validity_period =
            ogs_local_conf()->time.nf_instance.validity_duration;
        ogs_assert(SearchResult->validity_period);

        sendmsg.SearchResult = SearchResult;
        sendmsg.http.cache_control =
            ogs_msprintf("max-age=%d", SearchResult->validity_period);
        ogs_assert(sendmsg.http.cache_control);

        response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
        ogs_assert(response);

        (void)stage38_lab_instrument_discovery_response(
            response, recvmsg->param.target_nf_type);

        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        goto cleanup;

    } else if (discovery_option &&
            discovery_option->num_of_target_plmn_list &&
            discovery_option->num_of_requester_plmn_list) {

        /* No Discovery, Try to find different PLMN */

        bool rc;
        ogs_sbi_nf_instance_t *nf_instance = NULL;
        ogs_sbi_client_t *client = NULL;
        ogs_sbi_request_t *request = NULL;

        nrf_assoc_t *assoc = NULL;

        ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
            if (NF_INSTANCE_ID_IS_SELF(nf_instance->id))
                continue;

            if (nf_instance->nf_type != OpenAPI_nf_type_NRF)
                continue;

            if (ogs_sbi_discovery_option_target_plmn_list_is_matched(
                        nf_instance, discovery_option) == false)
                continue;

            break;
        }

        if (!nf_instance) {
            nf_instance = ogs_sbi_nf_instance_add();
            ogs_assert(nf_instance);
            ogs_sbi_nf_instance_set_type(nf_instance, OpenAPI_nf_type_NRF);

            /*
             * If nrf_nf_fsm_init() is not executed, nf_instance->sm is NULL.
             *
             * Since nf_instance->sm is NULL, nrf_nf_fsm_final()
             * is not executed later in nrf_context_final().
             */

            memcpy(nf_instance->plmn_id,
                    discovery_option->target_plmn_list,
                    sizeof(nf_instance->plmn_id));
            nf_instance->num_of_plmn_id =
                discovery_option->num_of_target_plmn_list;

            nf_instance->fqdn = ogs_nrf_fqdn_from_plmn_id(nf_instance->plmn_id);
            ogs_assert(nf_instance->fqdn);

            ogs_sbi_client_associate(nf_instance);
        }

        client = NF_INSTANCE_CLIENT(nf_instance);
        ogs_assert(client);

        /*
         * TS29.510
         * 5.3.2.4 Service Discovery in a different PLMN
         *
         * Then, steps 1-2 in Figure 5.3.2.2.3-1 are executed,
         * between the NRF in the Serving PLMN and the NRF in the Home PLMN.
         * In this step, the presence of the PLMN ID of the Home NRF
         * in the query parameter of the URI is not required.
         */
        discovery_option->num_of_target_plmn_list = 0;

        assoc = nrf_assoc_add(stream);
        if (!assoc) {
            ogs_error("nrf_assoc_add() failed");
            ogs_assert(true == ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "nrf_assoc_add() failed", NULL, NULL));
            goto cleanup;
        }

        request = ogs_nnrf_disc_build_discover(
                    recvmsg->param.target_nf_type,
                    recvmsg->param.requester_nf_type,
                    discovery_option);
        if (!request) {
            ogs_error("ogs_nnrf_disc_build_discover() failed");
            ogs_assert(true == ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "ogs_nnrf_disc_build_discover() failed", NULL,
                    NULL));
            nrf_assoc_remove(assoc);
            goto cleanup;
        }

        rc = ogs_sbi_send_request_to_client(
                client, discover_handler, request, assoc);
        if (rc == false) {
            ogs_error("ogs_sbi_send_request_to_client");
            ogs_assert(true == ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "ogs_sbi_send_request_to_client() failed", NULL,
                    NULL));
            ogs_sbi_request_free(request);
            nrf_assoc_remove(assoc);
            goto cleanup;
        }

        ogs_sbi_request_free(request);

    } else {

        /* No Discovery */

        sendmsg.SearchResult = SearchResult;

        response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        goto cleanup;
    }

cleanup:
    OpenAPI_list_for_each(SearchResult->nf_instances, node) {
        NFProfile = node->data;
        if (NFProfile) ogs_nnrf_nfm_free_nf_profile(NFProfile);
    }
    OpenAPI_list_free(SearchResult->nf_instances);

    if (sendmsg.http.cache_control)
        ogs_free(sendmsg.http.cache_control);

    ogs_free(SearchResult);

    return true;
}

static int discover_handler(
        int status, ogs_sbi_response_t *response, void *data)
{
    int rv;
    ogs_sbi_message_t message;

    nrf_assoc_t *assoc = data;
    ogs_sbi_stream_t *stream = NULL;

    ogs_assert(assoc);
    stream = assoc->stream;
    ogs_assert(stream);

    if (status != OGS_OK) {

        ogs_log_message(
                status == OGS_DONE ? OGS_LOG_DEBUG : OGS_LOG_WARN, 0,
                "response_handler() failed [%d]", status);

        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL,
                "response_handler() failed", NULL, NULL));

        nrf_assoc_remove(assoc);

        return OGS_ERROR;
    }

    ogs_assert(response);

    rv = ogs_sbi_parse_response(&message, response);
    if (rv != OGS_OK) {
        ogs_error("cannot parse HTTP response");
        goto cleanup;
    }

    if (message.res_status != OGS_SBI_HTTP_STATUS_OK) {
        ogs_error("NF-Discover failed [%d]", message.res_status);
        goto cleanup;
    }

    if (!message.SearchResult) {
        ogs_error("No SearchResult");
        goto cleanup;
    }

    handle_nf_discover_search_result(message.SearchResult);

cleanup:
    ogs_expect(true == ogs_sbi_server_send_response(stream, response));
    nrf_assoc_remove(assoc);
    ogs_sbi_message_free(&message);

    return OGS_OK;
}

static void handle_nf_discover_search_result(
        OpenAPI_search_result_t *SearchResult)
{
    OpenAPI_lnode_t *node = NULL;
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_assert(SearchResult);

    OpenAPI_list_for_each(SearchResult->nf_instances, node) {
        OpenAPI_nf_profile_t *NFProfile = NULL;

        if (!node->data) continue;

        NFProfile = node->data;

        if (!NFProfile) {
            ogs_error("No NFProfile");
            continue;
        }

        if (!NFProfile->nf_instance_id) {
            ogs_error("No NFProfile.NFInstanceId");
            continue;
        }

        if (!NFProfile->nf_type) {
            ogs_error("No NFProfile.NFType");
            continue;
        }

        if (!NFProfile->nf_status) {
            ogs_error("No NFProfile.NFStatus");
            continue;
        }

        nf_instance = ogs_sbi_nf_instance_find(NFProfile->nf_instance_id);
        if (!nf_instance) {
            nf_instance = ogs_sbi_nf_instance_add();
            ogs_assert(nf_instance);

            ogs_sbi_nf_instance_set_id(nf_instance, NFProfile->nf_instance_id);

            /*
             * If nrf_nf_fsm_init() is not executed, nf_instance->sm is NULL.
             *
             * Since nf_instance->sm is NULL, nrf_nf_fsm_final()
             * is not executed later in nrf_context_final().
             */

            ogs_info("[%s] (NF-discover) NF registered [type:%s]",
                    NFProfile->nf_instance_id,
                    OpenAPI_nf_type_ToString(NFProfile->nf_type));
        } else {

            ogs_warn("[%s] (NF-discover) NF has already been added [type:%s]",
                    NFProfile->nf_instance_id,
                    OpenAPI_nf_type_ToString(NFProfile->nf_type));
        }

        if (NF_INSTANCE_ID_IS_OTHERS(nf_instance->id)) {
            ogs_nnrf_nfm_handle_nf_profile(nf_instance, NFProfile);

            ogs_sbi_client_associate(nf_instance);

            switch (nf_instance->nf_type) {
            case OpenAPI_nf_type_SEPP:
                ogs_sbi_self()->sepp_instance = nf_instance;
                break;
            default:
                break;
            }

            ogs_info("[%s] (NF-discover) NF Profile updated [type:%s]",
                        nf_instance->id,
                        OpenAPI_nf_type_ToString(nf_instance->nf_type));
        }
    }
}
