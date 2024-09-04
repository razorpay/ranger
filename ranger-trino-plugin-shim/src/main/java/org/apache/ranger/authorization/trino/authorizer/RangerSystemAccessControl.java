/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ranger.authorization.trino.authorizer;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.ColumnSchema;
import io.trino.spi.connector.EntityKindAndName;
import io.trino.spi.connector.EntityPrivilege;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.QueryId;
import io.trino.spi.security.*;
import io.trino.spi.type.Type;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;

import javax.inject.Inject;
import java.security.Principal;
import java.util.*;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static final String RANGER_PLUGIN_TYPE = "trino";
  private static final String RANGER_TRINO_AUTHORIZER_IMPL_CLASSNAME = "org.apache.ranger.authorization.trino.authorizer.RangerSystemAccessControl";

  final private RangerPluginClassLoader rangerPluginClassLoader;
  final private SystemAccessControl systemAccessControlImpl;

  @Inject
  public RangerSystemAccessControl(RangerConfig config) {
    try {
      rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

      @SuppressWarnings("unchecked")
      Class<SystemAccessControl> cls = (Class<SystemAccessControl>) Class.forName(RANGER_TRINO_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

      activatePluginClassLoader();

      Map<String, String> configMap = new HashMap<>();
      if (config.getKeytab() != null && config.getPrincipal() != null) {
        configMap.put("ranger.keytab", config.getKeytab());
        configMap.put("ranger.principal", config.getPrincipal());
      }

      configMap.put("ranger.use_ugi", Boolean.toString(config.isUseUgi()));

      if (config.getHadoopConfigPath() != null) {
        configMap.put("ranger.hadoop_config", config.getHadoopConfigPath());
      }

      systemAccessControlImpl = cls.getDeclaredConstructor(Map.class).newInstance(configMap);
    } catch (Exception e) {
      throw new RuntimeException(e);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Deprecated
  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSystemSessionProperty(identity, propertyName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, QueryId queryId, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSystemSessionProperty(identity, queryId, propertyName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public boolean canAccessCatalog(SystemSecurityContext context, String catalogName) {
    try {
      activatePluginClassLoader();
      return systemAccessControlImpl.canAccessCatalog(context, catalogName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanCreateCatalog(SystemSecurityContext context, String catalog)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateCatalog(context, catalog);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropCatalog(SystemSecurityContext context, String catalog)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropCatalog(context, catalog);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
    Set<String> filteredCatalogs;
    try {
      activatePluginClassLoader();
      filteredCatalogs = systemAccessControlImpl.filterCatalogs(context, catalogs);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredCatalogs;
  }

  @Override
  public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema, Map<String, Object> properties) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateSchema(context, schema, properties);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropSchema(context, schema);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameSchema(context, schema, newSchemaName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowSchemas(context, catalogName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
    Set<String> filteredSchemas;
    try {
      activatePluginClassLoader();
      filteredSchemas = systemAccessControlImpl.filterSchemas(context, catalogName, schemaNames);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredSchemas;
  }

  @Override
  public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Object> properties) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateTable(context, table, properties);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropTable(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameTable(context, table, newTable);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
    Set<SchemaTableName> filteredTableNames;
    try {
      activatePluginClassLoader();
      filteredTableNames = systemAccessControlImpl.filterTables(context, catalogName, tableNames);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredTableNames;
  }

  @Override
  public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAddColumn(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropColumn(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameColumn(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanAlterColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAlterColumn(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetColumnComment(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetColumnComment(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanUpdateTableColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> updatedColumnNames) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanUpdateTableColumns(context, table, updatedColumnNames);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSelectFromColumns(context, table, columns);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetTableProperties(
          SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Optional<Object>> properties
  ) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetTableProperties(context, table, properties);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetViewComment(SystemSecurityContext context, CatalogSchemaTableName view){
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetViewComment(context, view);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanInsertIntoTable(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDeleteFromTable(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanTruncateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanTruncateTable(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateView(context, view);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropView(context, view);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateViewWithSelectFromColumns(context, table, columns);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetCatalogSessionProperty(context, catalogName, propertyName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanImpersonateUser(Identity identity, String userName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanImpersonateUser(identity, userName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Deprecated
  @Override
  public void checkCanExecuteQuery(Identity identity) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteQuery(identity);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanExecuteQuery(Identity identity, QueryId queryId) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteQuery(identity, queryId);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanViewQueryOwnedBy(Identity identity, Identity queryOwner) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanViewQueryOwnedBy(identity, queryOwner);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Collection<Identity> filterViewQueryOwnedBy(Identity identity, Collection<Identity> queryOwners) {
    Collection<Identity> filteredQueryOwners;
    try {
      activatePluginClassLoader();
      filteredQueryOwners = systemAccessControlImpl.filterViewQueryOwnedBy(identity, queryOwners);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredQueryOwners;
  }

  @Override
  public void checkCanKillQueryOwnedBy(Identity identity, Identity queryOwner) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanKillQueryOwnedBy(identity, queryOwner);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanReadSystemInformation(Identity identity) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanReadSystemInformation(identity);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanWriteSystemInformation(Identity identity) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanWriteSystemInformation(identity);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowCreateTable(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetTableComment(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowTables(context, schema);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowColumns(context, table);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public Set<String> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    Set<String> filteredColumns;
    try {
      activatePluginClassLoader();
      filteredColumns = systemAccessControlImpl.filterColumns(context, table, columns);
    } finally {
      deactivatePluginClassLoader();
    }
    return filteredColumns;
  }

  @Override
  public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameView(context, view, newView);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean withGrantOption) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanGrantTablePrivilege(context, privilege, table, grantee, withGrantOption);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal revokee, boolean grantOptionFor) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRevokeTablePrivilege(context, privilege, table, revokee, grantOptionFor);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanGrantEntityPrivilege(SystemSecurityContext context, EntityPrivilege privilege, EntityKindAndName entity, TrinoPrincipal grantee, boolean grantOption)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanGrantEntityPrivilege(context, privilege, entity, grantee, grantOption);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanDenyEntityPrivilege(SystemSecurityContext context, EntityPrivilege privilege, EntityKindAndName entity, TrinoPrincipal grantee)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDenyEntityPrivilege(context, privilege, entity, grantee);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanRevokeEntityPrivilege(SystemSecurityContext context, EntityPrivilege privilege, EntityKindAndName entity, TrinoPrincipal revokee, boolean grantOption)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRevokeEntityPrivilege(context, privilege, entity, revokee, grantOption);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public List<ViewExpression> getRowFilters(SystemSecurityContext context, CatalogSchemaTableName tableName) {
    List<ViewExpression> viewExpression;
    try {
      activatePluginClassLoader();
      viewExpression = systemAccessControlImpl.getRowFilters(context, tableName);
    } finally {
      deactivatePluginClassLoader();
    }
    return viewExpression;
  }

  @Override
  public Optional<ViewExpression> getColumnMask(SystemSecurityContext context, CatalogSchemaTableName tableName, String columnName, Type type) {
    Optional<ViewExpression> viewExpression;
    try {
      activatePluginClassLoader();
      viewExpression = systemAccessControlImpl.getColumnMask(context, tableName, columnName, type);
    } finally {
      deactivatePluginClassLoader();
    }
    return viewExpression;
  }

  @Override
  public Map<ColumnSchema, ViewExpression> getColumnMasks(SystemSecurityContext context, CatalogSchemaTableName tableName, List<ColumnSchema> columns) {
    Map<ColumnSchema, ViewExpression> colMasks;
    try {
      activatePluginClassLoader();
      colMasks = systemAccessControlImpl.getColumnMasks(context, tableName, columns);
    } finally {
      deactivatePluginClassLoader();
    }
    return colMasks;
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetUser(principal, userName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, TrinoPrincipal principal) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSchemaAuthorization(context, schema, principal);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowCreateSchema(SystemSecurityContext context, CatalogSchemaName schemaName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowCreateSchema(context, schemaName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanExecuteProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName procedure) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteProcedure(systemSecurityContext, procedure);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanExecuteTableProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaTableName table, String procedure) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteTableProcedure(systemSecurityContext, table, procedure);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public boolean canExecuteFunction(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName functionName) {
    try {
      activatePluginClassLoader();
      return systemAccessControlImpl.canExecuteFunction(systemSecurityContext, functionName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowFunctions(SystemSecurityContext systemSecurityContext, CatalogSchemaName schema)
  {
    // TODO: Override `filterFunctions` for filtering functions for unauthorized users. Check function comments in `super.checkCanShowFunctions`.
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowFunctions(systemSecurityContext, schema);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanShowCreateFunction(SystemSecurityContext context, CatalogSchemaRoutineName functionName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowCreateFunction(context, functionName);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  private void activatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.activate();
    }
  }

  private void deactivatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.deactivate();
    }
  }
}
