﻿using NTMiner.Controllers;
using NTMiner.Core;
using System;
using System.Collections.Generic;

namespace NTMiner.Service.ServerService {
    public class PoolServiceFace {
        private static readonly string SControllerName = RpcRoot.GetControllerName<IPoolController>();

        public PoolServiceFace() {
        }

        #region GetPools
        // TODO:异步化
        /// <summary>
        /// 同步方法
        /// </summary>
        /// <returns></returns>
        public List<PoolData> GetPools() {
            try {
                SignRequest request = new SignRequest {
                };
                DataResponse<List<PoolData>> response = RpcRoot.Post<DataResponse<List<PoolData>>>(NTMinerRegistry.GetControlCenterHost(), NTKeyword.ControlCenterPort, SControllerName, nameof(IPoolController.Pools), request, request, timeout: 2000);
                if (response != null && response.Data != null) {
                    return response.Data;
                }
                return new List<PoolData>();
            }
            catch (Exception e) {
                Logger.ErrorDebugLine(e);
                return new List<PoolData>();
            }
        }
        #endregion

        #region AddOrUpdatePoolAsync
        public void AddOrUpdatePoolAsync(PoolData entity, Action<ResponseBase, Exception> callback) {
            DataRequest<PoolData> request = new DataRequest<PoolData> {
                Data = entity
            };
            RpcRoot.PostAsync(NTMinerRegistry.GetControlCenterHost(), NTKeyword.ControlCenterPort, SControllerName, nameof(IPoolController.AddOrUpdatePool), request, request, callback);
        }
        #endregion

        #region RemovePoolAsync
        public void RemovePoolAsync(Guid id, Action<ResponseBase, Exception> callback) {
            DataRequest<Guid> request = new DataRequest<Guid>() {
                Data = id
            };
            RpcRoot.PostAsync(NTMinerRegistry.GetControlCenterHost(), NTKeyword.ControlCenterPort, SControllerName, nameof(IPoolController.RemovePool), request, request, callback);
        }
        #endregion
    }
}
