#include "ox_access.h"

static int _access_atoi(u_char *line, size_t n);
static u_char *_access_strlchr(u_char *p, u_char *last, u_char c);
static in_addr_t _access_inet_addr(u_char *text, size_t len);
static int _access_stor(u_char *text, size_t text_len, ox_access_rule_t *rule);
ox_access_conf_t * ox_access_get(const char *acc_str);
int ox_access_inet(ox_access_conf_t *cf, in_addr_t addr);
void ox_access_free(ox_access_conf_t *cf);

static int _access_atoi(u_char *line, size_t n)
{
  int value;

  if (n == 0) {
    return OX_ERROR;
  }

  for (value = 0; n--; line++) {
    if (*line < '0' || *line > '9') {
      return OX_ERROR;
    }
    value = value * 10 + (*line - '0');
  }

  if (value < 0) {
    return OX_ERROR;
  }
  else {
    return value;
  }
}

static u_char * _access_strlchr(u_char *p, u_char *last, u_char c)
{
  while (p < last) {
    if (*p == c) {
      return p;
    }
    p++;
  }
  return NULL;
}

static in_addr_t _access_inet_addr(u_char *text, size_t len)
{
  u_char *p, c;
  in_addr_t addr = 0;
  uint octet = 0, n = 0;

  for (p = text; p < text + len; p++) {
    c = *p;
    if (c >= '0' && c <= '9') {
      octet = octet * 10 + (c - '0');
      continue;
    }
    if (c == '.' && octet < 256) {
      addr = (addr << 8) + octet;
      octet = 0;
      n++;
      continue;
    }
    return INADDR_NONE;
  }

  if (n == 3 && octet < 256) {
    addr = (addr << 8) + octet;
    return htonl(addr);
  }
  return INADDR_NONE;
}

static int _access_stor(u_char *text, size_t text_len, ox_access_rule_t *rule)
{
  u_char *addr, *mask, *last;
  size_t len;
  int shift;
  addr = text;
  last = addr + text_len;

  mask = _access_strlchr(addr, last, '/');
  len = (mask ? mask : last) - addr;

  rule->addr = _access_inet_addr(addr, len);

  if (rule->addr != INADDR_NONE) {
    if (mask == NULL) {
      rule->mask = 0xffffffff;
      return OX_OK;
    }
  }
  else {
    return OX_ERROR;
  }

  mask++;

  shift = _access_atoi(mask, last - mask);
  if (shift == OX_ERROR) {
    return OX_ERROR;
  }
  if (shift > 32) {
    return OX_ERROR;
  }
  if (shift) {
    rule->mask = htonl((uint32_t) (0xffffffffu << (32 - shift)));
  }
  else {
    /*
     * x86 compilers use a shl instruction that
     * shifts by modulo 32
     */
    rule->mask = 0;
  }

  if (rule->addr == (rule->addr & rule->mask)) {
    return OX_OK;
  }
  rule->addr &= rule->mask;

  return OX_OK;
}

ox_access_conf_t * ox_access_get(const char *acc_str)
{
  if(acc_str == NULL) {
    return NULL;
  }
  ox_access_conf_t *acconf = (ox_access_conf_t *)malloc(sizeof(ox_access_conf_t));
  if(acconf == NULL) {
    return NULL;
  }
  acconf->n = 0;
  acconf->rules = NULL;
  size_t acc_len = strlen(acc_str);
  char *acc = (char *)malloc(acc_len);
  if(acc == NULL) {
    return NULL;
  }
  strncpy(acc, acc_str, acc_len);
  char *start = acc, *end;
  while(start <= acc + acc_len) {
    end = strchr(start, ';');
    end = (end) ? end : acc+acc_len;
    char *mode = start;
    char *range = strchr(mode, ' ');
    if (range) {
      ox_access_rule_t *this_rule = (ox_access_rule_t *)malloc(sizeof(ox_access_rule_t));
      if (this_rule == NULL) {
        start = end + 1;
        continue;
      }
      (void) memset(this_rule, 0, sizeof(ox_access_rule_t));
      this_rule->deny = (mode[0] == 'd') ? 1 : 0;
      size_t range_len;
      range++;
      range_len = end - range;

      uint all = (range_len == 3 && strstr(range, "all") == range);

      if (!all) {
        int rc;
        rc = _access_stor((unsigned char *)range, range_len, this_rule);
        if (rc == OX_ERROR) {
          start = end + 1;
          continue;
        }
      }

      ox_access_rules_t *rules = (ox_access_rules_t *)malloc(sizeof(ox_access_rules_t));
      if (rules == NULL) {
        start = end + 1;
        continue;
      }

      rules->value= this_rule;
      rules->next = acconf->rules;
      acconf->rules = rules;
      acconf->n++;
    }
    start = end + 1;
  }
  free(acc);
  return acconf;
}

int ox_access_inet(ox_access_conf_t *cf, in_addr_t addr)
{
  ox_access_rules_t *rules = cf->rules;
  if(rules == NULL) {
    LOG_PRINT(LOG_DEBUG, "rules nil");
    return OX_OK;
  }
  LOG_PRINT(LOG_DEBUG, "rules: %p", rules);

  while(rules) {
    LOG_PRINT(LOG_DEBUG, "addr: %d", addr);
    LOG_PRINT(LOG_DEBUG, "rules->value->addr: %d", rules->value->addr);
    LOG_PRINT(LOG_DEBUG, "rules->value->mask: %d", rules->value->mask);
    if ((addr & rules->value->mask) == rules->value->addr) {
      if (rules->value->deny) {
        //LOG_PRINT(LOG_INFO, "deny");
        return OX_FORBIDDEN;
      }
      return OX_OK;
    }
    rules = rules->next;
  }

  return OX_FORBIDDEN;
}

void ox_access_free(ox_access_conf_t *cf)
{
  if (cf == NULL) {
    return;
  }
  ox_access_rules_t *rules = cf->rules;
  while(rules) {
    cf->rules = rules->next;
    free(rules->value);
    free(rules);
    rules = cf->rules;
  }
  free(cf);
}
