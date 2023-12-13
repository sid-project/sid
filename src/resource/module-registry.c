/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
 *
 * SID is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * SID is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SID.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "internal/common.h"

#include "resource/module-registry.h"

#include "internal/mem.h"
#include "internal/util.h"
#include "log/log.h"
#include "resource/resource.h"

#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>

const sid_resource_type_t sid_resource_type_module;

struct module_registry {
	const char                  *directory;
	char                        *base_name;
	const char                  *module_prefix;
	const char                  *module_suffix;
	uint64_t                     flags;
	void                        *cb_arg;
	unsigned                     symbol_count;
	struct module_symbol_params *symbol_params;
	sid_resource_iter_t         *module_iter;
};

struct module {
	struct module_registry *registry;
	module_cb_fn_t         *init_fn;
	module_cb_fn_t         *exit_fn;
	module_cb_fn_t         *reset_fn;
	char                   *full_name;
	char                   *name;
	char                   *aliases;
	void                   *handle;
	void                  **symbols;
	void                   *data;
};

static int _set_module_name(struct module_registry *registry, struct module *module, const char *name)
{
	char *orig_full_name = module->full_name;
	char *orig_name      = module->name;

	if (!(module->full_name = util_str_comb_to_str(NULL, registry->base_name, MODULE_NAME_DELIM, name))) {
		if (orig_full_name) {
			module->full_name = orig_full_name;
			module->name      = orig_name;
		}

		return -ENOMEM;
	}

	module->name = strrchr(module->full_name, '/') + 1;
	free(orig_full_name);

	return 0;
}

static sid_resource_t *_find_module(sid_resource_t *mod_registry_res, const char *module_name)
{
	struct module_registry *registry = sid_resource_get_data(mod_registry_res);
	sid_resource_t         *res, *found = NULL;
	struct module          *module;
	char                   *alias;
	size_t                  len;

	sid_resource_iter_reset(registry->module_iter);
	while ((res = sid_resource_iter_next(registry->module_iter))) {
		if (sid_resource_match(res, &sid_resource_type_module, NULL)) {
			module = sid_resource_get_data(res);

			if (!strcmp(module->name, module_name))
				found = res;
			else if (module->aliases) {
				for (alias = module->aliases; (len = strlen(alias)); alias += len) {
					if (!strcmp(alias, module_name)) {
						found = res;
						break;
					}
				}
			}

			if (found)
				break;
		}
	}

	return found;
}

sid_resource_t *module_registry_load_module(sid_resource_t *mod_registry_res, const char *module_name)
{
	struct module_registry *registry;
	sid_resource_t         *mod_res;

	if (!sid_resource_match(mod_registry_res, &sid_resource_type_module_registry, NULL) || UTIL_STR_EMPTY(module_name))
		return NULL;

	registry = sid_resource_get_data(mod_registry_res);

	if ((mod_res = _find_module(mod_registry_res, module_name))) {
		sid_resource_log_debug(mod_registry_res,
		                       "Module %s/%s already loaded, skipping load request.",
		                       registry->directory,
		                       module_name);
		return mod_res;
	}

	if (!(mod_res = sid_resource_create(mod_registry_res,
	                                    &sid_resource_type_module,
	                                    SID_RESOURCE_RESTRICT_WALK_UP | SID_RESOURCE_DISALLOW_ISOLATION,
	                                    module_name,
	                                    NULL,
	                                    SID_RESOURCE_PRIO_NORMAL,
	                                    SID_RESOURCE_NO_SERVICE_LINKS))) {
		sid_resource_log_debug(mod_registry_res, "Failed to load module %s/%s.", registry->directory, module_name);
		return NULL;
	}

	return mod_res;
}

sid_resource_t *module_registry_get_module(sid_resource_t *mod_registry_res, const char *module_name)
{
	if (!sid_resource_match(mod_registry_res, &sid_resource_type_module_registry, NULL) || UTIL_STR_EMPTY(module_name))
		return NULL;

	return _find_module(mod_registry_res, module_name);
}

int module_registry_unload_module(sid_resource_t *mod_res)
{
	if (!sid_resource_match(mod_res, &sid_resource_type_module, NULL))
		return -EINVAL;

	return sid_resource_unref(mod_res);
}

int module_registry_get_module_symbols(sid_resource_t *mod_res, const void ***ret)
{
	struct module *module;

	if (!sid_resource_match(mod_res, &sid_resource_type_module, NULL) || !ret)
		return -EINVAL;

	module = sid_resource_get_data(mod_res);
	*ret   = (const void **) module->symbols;

	return 0;
}

static const char mod_reset_failed_msg[] = "Module-specific reset failed.";

int module_registry_reset_modules(sid_resource_t *mod_registry_res)
{
	struct module_registry *registry;
	sid_resource_t         *mod_res;
	struct module          *module;

	if (!sid_resource_match(mod_registry_res, &sid_resource_type_module_registry, NULL))
		return -EINVAL;

	registry = sid_resource_get_data(mod_registry_res);
	sid_resource_iter_reset(registry->module_iter);

	while ((mod_res = sid_resource_iter_next(registry->module_iter))) {
		module = sid_resource_get_data(mod_res);

		/* detect changed registry base name and reset modules' full name if needed accordingly */
		if (strncmp(module->full_name, registry->base_name, strlen(registry->base_name)))
			_set_module_name(registry, module, module->name);

		if (module->reset_fn && module->reset_fn(mod_res, registry->cb_arg) < 0)
			sid_resource_log_debug(mod_res, mod_reset_failed_msg);
	}

	return 0;
}

int module_registry_reset_module(sid_resource_t *mod_res)
{
	struct module *module;

	if (!sid_resource_match(mod_res, &sid_resource_type_module, NULL))
		return -EINVAL;

	module = sid_resource_get_data(mod_res);

	if (module->reset_fn && module->reset_fn(mod_res, module->registry->cb_arg) < 0) {
		sid_resource_log_debug(mod_res, mod_reset_failed_msg);
		return -1;
	}

	return 0;
}

const char *module_get_full_name(sid_resource_t *mod_res)
{
	if (!mod_res || !sid_resource_match(mod_res, &sid_resource_type_module, NULL))
		return NULL;

	return ((struct module *) sid_resource_get_data(mod_res))->full_name;
}

const char *module_get_name(sid_resource_t *mod_res)
{
	if (!mod_res || !sid_resource_match(mod_res, &sid_resource_type_module, NULL))
		return NULL;

	return ((struct module *) sid_resource_get_data(mod_res))->name;
}

void module_set_data(sid_resource_t *mod_res, void *data)
{
	if (!mod_res || !sid_resource_match(mod_res, &sid_resource_type_module, NULL))
		return;

	((struct module *) sid_resource_get_data(mod_res))->data = data;
}

void *module_get_data(sid_resource_t *mod_res)
{
	if (!mod_res || !sid_resource_match(mod_res, &sid_resource_type_module, NULL))
		return NULL;

	return ((struct module *) sid_resource_get_data(mod_res))->data;
}

int module_registry_add_module_subregistry(sid_resource_t *mod_res, sid_resource_t *mod_subregistry_res)
{
	struct module          *module;
	struct module_registry *subregistry;
	char                   *orig_base_name;

	if (!sid_resource_match(mod_res, &sid_resource_type_module, NULL) ||
	    !sid_resource_match(mod_subregistry_res, &sid_resource_type_module_registry, NULL))
		return -EINVAL;

	/*
	 * Check subregistry does not have any existing parent,
	 * because we need to make the module as subregistry's parent here.
	 */
	if (sid_resource_has_parent(mod_subregistry_res))
		return -EINVAL;

	module         = sid_resource_get_data(mod_res);
	subregistry    = sid_resource_get_data(mod_subregistry_res);

	orig_base_name = subregistry->base_name;

	/*
	 * Subregistry's new base name is:
	 *   <module full name>/<subregistry base name>
	 *
	 * If setting the new base name fails, revert to the original base name.
	 */
	if (!(subregistry->base_name = util_str_comb_to_str(NULL, NULL, module->full_name, subregistry->base_name))) {
		subregistry->base_name = orig_base_name;
		return -ENOMEM;
	}

	/*
	 * Reset any modules that the subregistry might have already loaded to account
	 * for the new base name and finally attach the subregistry to the module.
	 *
	 * If anything fails, revert to the original base name and reset again.
	 */
	if (module_registry_reset_modules(mod_subregistry_res) < 0 ||
	    sid_resource_add_child(mod_res, mod_subregistry_res, SID_RESOURCE_RESTRICT_WALK_UP | SID_RESOURCE_DISALLOW_ISOLATION)) {
		free(subregistry->base_name);
		subregistry->base_name = orig_base_name;
		(void) module_registry_reset_modules(mod_subregistry_res);
		return -1;
	}

	free(orig_base_name);
	return 0;
}

static int _load_modules(sid_resource_t *mod_registry_res)
{
	struct module_registry *registry = sid_resource_get_data(mod_registry_res);
	char                    name_buf[MODULE_NAME_MAX_LEN + 1];
	util_mem_t              mem    = {.base = name_buf, .size = sizeof(name_buf)};
	struct dirent         **dirent = NULL;
	size_t                  prefix_len, suffix_len;
	char                   *name;
	int                     count, i;
	int                     r = 0;

	count                     = scandir(registry->directory, &dirent, NULL, versionsort);

	if (count < 0) {
		sid_resource_log_sys_error(mod_registry_res, "scandir", registry->directory);
		r = -1;
		goto out;
	}

	prefix_len = registry->module_prefix ? strlen(registry->module_prefix) : 0;
	suffix_len = registry->module_suffix ? strlen(registry->module_suffix) : 0;

	for (i = 0; i < count; i++) {
		if (dirent[i]->d_name[0] != '.' &&
		    util_str_combstr(dirent[i]->d_name, registry->module_prefix, NULL, registry->module_suffix, 1)) {
			if (!(name = util_str_copy_substr(&mem,
			                                  dirent[i]->d_name,
			                                  prefix_len,
			                                  strlen(dirent[i]->d_name) - prefix_len - suffix_len))) {
				sid_resource_log_debug(mod_registry_res, "Failed to copy name out of %s.", dirent[i]->d_name);
				free(dirent[i]);
				continue;
			}

			if (!sid_resource_create(mod_registry_res,
			                         &sid_resource_type_module,
			                         SID_RESOURCE_RESTRICT_WALK_UP | SID_RESOURCE_DISALLOW_ISOLATION,
			                         name,
			                         registry,
			                         SID_RESOURCE_PRIO_NORMAL,
			                         SID_RESOURCE_NO_SERVICE_LINKS))
				sid_resource_log_error(mod_registry_res,
				                       "Failed to load module %s/%s.",
				                       registry->directory,
				                       dirent[i]->d_name);
		}

		free(dirent[i]);
	}
out:
	free(dirent);
	return r;
}

int module_registry_load_modules(sid_resource_t *mod_registry_res)
{
	if (!sid_resource_match(mod_registry_res, &sid_resource_type_module_registry, NULL))
		return -EINVAL;

	if (_load_modules(mod_registry_res) < 0) {
		sid_resource_log_error(mod_registry_res,
		                       "Failed to load modules from directory %s.",
		                       ((struct module_registry *) sid_resource_get_data(mod_registry_res))->directory);
		return -1;
	}

	return 0;
}

typedef void (*generic_t)(void);

static int _load_module_symbol(sid_resource_t                    *mod_res,
                               void                              *dl_handle,
                               const struct module_symbol_params *params,
                               void                             **symbol_store)
{
	void *symbol;
	int   r = -1;

	if (!(symbol = dlsym(dl_handle, params->name))) {
		if (params->flags & MODULE_SYMBOL_FAIL_ON_MISSING) {
			sid_resource_log_debug(mod_res, "Failed to load symbol %s: %s.", params->name, dlerror());
			goto out;
		} else if (params->flags & MODULE_SYMBOL_WARN_ON_MISSING)
			sid_resource_log_warning(mod_res, "Symbol %s not loaded.", params->name);
	}

	r = 0;
out:
	if (params->flags & MODULE_SYMBOL_INDIRECT)
		symbol = symbol ? *((generic_t **) symbol) : NULL;

	*symbol_store = symbol;
	return r;
}

#define MODULE_PRIO_NAME    "module_prio"
#define MODULE_ALIASES_NAME "module_aliases"
#define MODULE_INIT_NAME    "module_init"
#define MODULE_EXIT_NAME    "module_exit"
#define mod_resET_NAME      "mod_reset"

static int _init_module(sid_resource_t *mod_res, const void *kickstart_data, void **data)
{
	struct module_registry     *registry      = (struct module_registry *) kickstart_data;
	struct module_symbol_params symbol_params = {0};
	struct module              *module        = NULL;
	char                        path[PATH_MAX];
	int64_t                    *p_prio;
	char                      **p_aliases;
	unsigned                    i;
	int                         r;

	if (!(module = mem_zalloc(sizeof(*module)))) {
		sid_resource_log_debug(mod_res, "Failed to allocate module structure.");
		goto fail;
	}

	module->registry = registry;

	if ((r = _set_module_name(registry, module, sid_resource_get_id(mod_res))) < 0) {
		sid_resource_log_error_errno(mod_res, r, "Failed to set module name");
		goto fail;
	}

	if (!(module->symbols = mem_zalloc(registry->symbol_count * sizeof(void *)))) {
		sid_resource_log_debug(mod_res, "Failed to allocate array to store symbol pointers.");
		goto fail;
	}

	if (snprintf(path,
	             sizeof(path) - 1,
	             "%s/%s%s%s",
	             registry->directory,
	             registry->module_prefix ?: "",
	             module->name,
	             registry->module_suffix ?: "") < 0) {
		sid_resource_log_debug(mod_res, "Failed to create module path.");
		goto fail;
	}

	if (!(module->handle = dlopen(path, RTLD_NOW))) {
		sid_resource_log_debug(mod_res, "Failed to open module: %s.", dlerror());
		goto fail;
	}

	/* module priority value is direct symbol */
	symbol_params.name = MODULE_PRIO_NAME;
	if (_load_module_symbol(mod_res, module->handle, &symbol_params, (void **) &p_prio) < 0)
		goto fail;

	if (p_prio && (sid_resource_set_prio(mod_res, *p_prio) < 0))
		goto fail;

	/* module aliases value is direct symbol */
	symbol_params.name = MODULE_ALIASES_NAME;
	if (_load_module_symbol(mod_res, module->handle, &symbol_params, (void **) &p_aliases) < 0)
		goto fail;

	// FIXME: Add check that no other module uses any of the aliases or name.

	if (p_aliases)
		module->aliases = *p_aliases;

	/* function symbols are indirect symbols */
	symbol_params.flags = MODULE_SYMBOL_INDIRECT;

	symbol_params.name  = mod_resET_NAME;
	if (_load_module_symbol(mod_res, module->handle, &symbol_params, (void **) &module->reset_fn) < 0)
		goto fail;

	symbol_params.flags |= MODULE_SYMBOL_FAIL_ON_MISSING;
	symbol_params.name   = MODULE_INIT_NAME;
	if (_load_module_symbol(mod_res, module->handle, &symbol_params, (void **) &module->init_fn) < 0)
		goto fail;

	symbol_params.name = MODULE_EXIT_NAME;
	if (_load_module_symbol(mod_res, module->handle, &symbol_params, (void **) &module->exit_fn) < 0)
		goto fail;

	for (i = 0; i < registry->symbol_count; i++) {
		if (_load_module_symbol(mod_res, module->handle, &registry->symbol_params[i], &module->symbols[i]) < 0)
			goto fail;
	}

	*data = module;

	if (module->init_fn(mod_res, registry->cb_arg) < 0) {
		sid_resource_log_debug(mod_res, "Module-specific initialization failed.");
		goto fail;
	}

	return 0;
fail:
	if (module) {
		if (module->handle)
			(void) dlclose(module->handle);
		free(module->full_name);
		free(module->symbols);
		free(module);
	}
	return -1;
}

static int _destroy_module(sid_resource_t *mod_res)
{
	struct module *module = sid_resource_get_data(mod_res);

	if (module->exit_fn(mod_res, module->registry->cb_arg) < 0)
		sid_resource_log_debug(mod_res, "Module-specific finalization failed.");

	if (dlclose(module->handle) < 0)
		sid_resource_log_debug(mod_res, "Failed to close %s module handle: %s.", module->name, dlerror());

	free(module->symbols);
	free(module->full_name);
	free(module);
	return 0;
}

static void _free_module_registry(struct module_registry *registry)
{
	unsigned i;

	if (!registry)
		return;

	sid_resource_iter_destroy(registry->module_iter);

	if (registry->symbol_params) {
		for (i = 0; i < registry->symbol_count; i++)
			free((void *) registry->symbol_params[i].name);
		free(registry->symbol_params);
	}

	free((void *) registry->base_name);
	free((void *) registry->directory);
	free((void *) registry->module_prefix);
	free((void *) registry->module_suffix);
	free(registry);
}

static int _init_module_registry(sid_resource_t *mod_registry_res, const void *kickstart_data, void **data)
{
	const struct module_registry_resource_params *params   = kickstart_data;
	struct module_registry                       *registry = NULL;
	unsigned                                      i, symbol_count = 0;

	if (!params) {
		sid_resource_log_debug(mod_registry_res, "Module resource parameters not specified.");
		goto fail;
	}

	if (!params->directory || !*params->directory) {
		sid_resource_log_debug(mod_registry_res, "Module directory not specified.");
		goto fail;
	}

	while (params->symbol_params[symbol_count].name)
		symbol_count++;

	if (!symbol_count) {
		sid_resource_log_debug(mod_registry_res, "Module's symbol parameters not specified.");
		goto fail;
	}

	if (!(registry = mem_zalloc(sizeof(*registry)))) {
		sid_resource_log_debug(mod_registry_res, "Failed to allocate module reigistry structure.");
		goto fail;
	}

	if (!(registry->base_name = util_str_comb_to_str(NULL, MODULE_NAME_DELIM, sid_resource_get_id(mod_registry_res), NULL))) {
		sid_resource_log_debug(mod_registry_res, "Failed to set base name.");
		goto fail;
	}

	registry->symbol_count = symbol_count;

	if (!(registry->directory = strdup(params->directory))) {
		sid_resource_log_debug(mod_registry_res, "Failed to copy module directory name.");
		goto fail;
	}

	if (params->module_prefix && *params->module_prefix && !(registry->module_prefix = strdup(params->module_prefix))) {
		sid_resource_log_debug(mod_registry_res, "Failed to copy common module prefix.");
		goto fail;
	}

	if (params->module_suffix && *params->module_suffix && !(registry->module_suffix = strdup(params->module_suffix))) {
		sid_resource_log_debug(mod_registry_res, "Failed to copy common module suffix.");
		goto fail;
	}

	if (!(registry->symbol_params = mem_zalloc(symbol_count * sizeof(struct module_symbol_params)))) {
		sid_resource_log_debug(mod_registry_res, "Failed to allocate memory for symbol parameters.");
		goto fail;
	}

	for (i = 0; i < symbol_count; i++) {
		if (!(registry->symbol_params[i].name = strdup(params->symbol_params[i].name))) {
			sid_resource_log_debug(mod_registry_res, "Failed to copy symbol name.");
			goto fail;
		}
		registry->symbol_params[i].flags = params->symbol_params[i].flags;
	}

	registry->flags  = params->flags;
	registry->cb_arg = params->cb_arg;

	*data            = registry;

	if (!(registry->module_iter = sid_resource_iter_create(mod_registry_res))) {
		sid_resource_log_debug(mod_registry_res, "Failed to prepare iterator for modules in module registry.");
		goto fail;
	}

	if ((registry->flags & MODULE_REGISTRY_PRELOAD) && _load_modules(mod_registry_res) < 0) {
		sid_resource_log_debug(mod_registry_res, "Failed to preload modules from directory %s.", registry->directory);
		goto fail;
	}

	return 0;
fail:
	_free_module_registry(registry);
	return -1;
}

static int _destroy_module_registry(sid_resource_t *mod_registry_res)
{
	_free_module_registry(sid_resource_get_data(mod_registry_res));
	return 0;
}

const sid_resource_type_t sid_resource_type_module = {
	.name        = "module",
	.short_name  = "mod",
	.description = "Resource representing a single module with loaded symbols.",
	.init        = _init_module,
	.destroy     = _destroy_module,
	.log_pfx     = (log_pfx_t) {.s = "mod", .n = NULL},
};

const sid_resource_type_t sid_resource_type_module_registry = {
	.name        = "module-registry",
	.short_name  = "mrg",
	.description = "Resource providing module registration and loading.",
	.init        = _init_module_registry,
	.destroy     = _destroy_module_registry,
};
