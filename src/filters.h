#ifndef FILTERS_H
#define FILTERS_H
#ifdef __cplusplus
extern "C" {
#endif

void filter_set_parameter(struct Ferret *ferret, const char *name, const char *value);

void filter_eval(const struct SniffFilter *flt, const struct NetFrame *frame, unsigned *include, unsigned *exclude);

#ifdef __cplusplus
}
#endif
#endif